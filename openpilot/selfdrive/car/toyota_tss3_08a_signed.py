"""Exact-F33 authenticated comma-owned 0x08A request plane.

The FRC supplies only publication cadence and SecOC freshness generations.
Openpilot constructs the complete application, the EPS RAM resident signs it,
and Panda replaces the corresponding native publication downstream.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from opendbc.car import structs
from opendbc.car.can_definitions import CanData
from opendbc.car.secoc import attach_authenticator
from opendbc.car.toyota.tss3 import (
  build_host_application,
  target_angle_deg_to_raw,
)
from opendbc.car.toyota.values import CAR, ToyotaSafetyFlags
from openpilot.common.swaglog import cloudlog

NATIVE_08A_ADDR = 0x08A
SECOC_SYNC_ADDR = 0x00F
ADMIN_ADDR = 0x777
UPSTREAM_BUS = 2
SYNC_BUS = 0
DOWNSTREAM_BUS = 0
ADMIN_BUS = 1
PANDA_RETURNED_OFFSET = 0x80
PANDA_REJECTED_OFFSET = 0xC0
SendCan = Callable[[list[CanData]], None]

ORACLE_REQUEST_ADDR = 0x1FDC0002
ORACLE_RESPONSE_ADDR = 0x1FE00002
ORACLE_BUS = 0
ORACLE_PRIVATE_SID = 0xC9
ORACLE_SEQUENCE_MAX = 0x1F
ORACLE_MAX_PENDING_GENERATIONS = 8
# Recorded driving qualification: 39,071 raw-oracle attempts, p99 below 30 ms,
# max 34.03 ms. A missing response is not authority loss: retry the same source
# generation after 50 ms. Every generation still has to publish within 90 ms of
# its native arrival, before Panda's 100 ms replacement watchdog fails open.
ORACLE_RETRY_TIMEOUT_S = 0.050
ORACLE_PUBLICATION_DEADLINE_S = 0.090

def decode_sync(data: bytes) -> tuple[int, int]:
  if len(data) != 8:
    raise ValueError("0x00F sync frame must be 8 bytes")
  trip = int.from_bytes(data[0:2], "big")
  reset = (data[2] << 12) | (data[3] << 4) | (data[4] >> 4)
  return trip, reset


def make_admin(arm: bool) -> CanData:
  return CanData(ADMIN_ADDR, bytes((7, 0xC9, 0xA8, int(arm), 0, 0, 0, 0)), ADMIN_BUS)


def request_plane_enabled(CP: structs.CarParams) -> bool:
  return (CP.carFingerprint == CAR.TOYOTA_CAMRY_TSS3 and not CP.passive and bool(CP.safetyConfigs) and
          bool(CP.safetyConfigs[0].safetyParam & ToyotaSafetyFlags.TSS3_08A_HOST.value))


def shift_reset_epoch(trip_counter: int, reset_counter: int, delta: int) -> tuple[int, int]:
  packed = (((trip_counter << 20) | reset_counter) + delta) & ((1 << 36) - 1)
  return packed >> 20, packed & ((1 << 20) - 1)


def resolve_epoch(sync_trip: int, sync_reset: int, reset_low2: int) -> tuple[int, int] | None:
  # 0x00F and 0x08A can straddle the same reset transition. Native FV4 selects
  # the generation; 0x00F only supplies the nearby full reset/trip value.
  for delta in (0, -1, 1, -2, 2):
    trip, reset = shift_reset_epoch(sync_trip, sync_reset, delta)
    if (reset & 0x3) == reset_low2:
      return trip, reset
  return None


def build_oracle_transport(seq: int, application: bytes, message_counter: int, reset_counter: int) -> list[CanData]:
  """Build one stateless raw-classic signer transaction.

  Four fragments carry the exact 28 application bytes. The fifth carries only
  freshness metadata and a fixed trailer. All five are submitted together; the
  EPS resident reads them from the pre-staging RX ring, so there is no ISO-TP
  flow-control or receiver-paced transport state.
  """
  if not 1 <= seq <= ORACLE_SEQUENCE_MAX:
    raise ValueError(f"oracle sequence must be 1..{ORACLE_SEQUENCE_MAX}")
  if len(application) != 28:
    raise ValueError("oracle application must be exactly 28 bytes")
  if not 0 <= message_counter <= 0xFF:
    raise ValueError("oracle message counter must fit u8")

  frames = []
  for fragment in range(4):
    header = (fragment << 5) | seq
    frames.append(CanData(ORACLE_REQUEST_ADDR,
                          bytes((header,)) + application[fragment * 7:(fragment + 1) * 7],
                          ORACLE_BUS))
  frames.append(CanData(ORACLE_REQUEST_ADDR,
                        bytes(((4 << 5) | seq, message_counter, reset_counter & 0xFF,
                               ORACLE_PRIVATE_SID, 0xA8, seq ^ 0xFF, 0x5A, 0xA5)),
                        ORACLE_BUS))
  return frames


@dataclass(frozen=True)
class NativeEvent:
  index: int
  b26: int
  trip_counter: int
  reset_counter: int
  message_low2: int


class NativeFreshnessTracker:
  """Recover freshness passively at a native reset boundary, then track +1."""

  def __init__(self) -> None:
    self.event: NativeEvent | None = None
    self.message_counter: int | None = None

  @property
  def ready(self) -> bool:
    return self.message_counter is not None

  def reset(self) -> None:
    self.event = None
    self.message_counter = None

  def update(self, event: NativeEvent) -> tuple[bool, bool]:
    """Return (ready, lost_ready_state).

    Native F33 starts each reset epoch at message counter 1 and advances B26 by
    one per publication. Waiting for the next observed epoch boundary therefore
    removes the need to brute-force the hidden high message-counter bits.
    """
    prev = self.event
    was_ready = self.ready
    self.event = event
    if prev is None:
      return False, False

    if ((event.b26 - prev.b26) & 0x3F) != 1:
      self.message_counter = None
      return False, was_ready

    reset_changed = (event.trip_counter, event.reset_counter) != (prev.trip_counter, prev.reset_counter)
    if not was_ready:
      if reset_changed and event.message_low2 == 1:
        self.message_counter = 1
        return True, False
      return False, False

    if reset_changed:
      if event.message_low2 != 1:
        self.message_counter = None
        return False, True
      self.message_counter = 1
      return True, False

    message_counter = (int(self.message_counter) + 1) & 0xFF
    if (message_counter & 0x3) != event.message_low2:
      self.message_counter = None
      return False, True
    self.message_counter = message_counter
    return True, False


@dataclass
class SignJob:
  native_index: int
  application: bytes
  reset_counter: int
  message_counter: int
  queued_at: float
  sent_at: float | None = None
  attempts: int = 0


class ToyotaTss3RequestProxy:
  """Minimal asynchronous signer/forwarding adapter for exact-F33 0x08A."""

  def __init__(self, send_can: SendCan, *, start_thread: bool = True, monotonic=time.monotonic):
    self._send_can = send_can
    self._monotonic = monotonic
    self._cv = threading.Condition(threading.RLock())
    self._stop = False
    self._thread: threading.Thread | None = None

    self.can_valid = False
    self.control_enabled = False
    self.control_lat_active = False
    self.control_target_angle_raw = 0
    self.control_long_active = False
    self.control_accel = 0.0
    self.control_set_speed_kph = 0.0
    self.sync_trip: int | None = None
    self.sync_reset: int | None = None
    self.native_index = 0
    self.tracker = NativeFreshnessTracker()

    self.jobs: deque[SignJob] = deque()
    self.inflight: tuple[int, SignJob] | None = None
    self.next_oracle_seq = 1

    self.active = False
    self.arm_pending = False
    self.arm_host_frame: bytes | None = None

    self.last_failure_reason = ""

    if start_thread:
      self._thread = threading.Thread(target=self._oracle_sender_loop, name="tss3_08a_oracle", daemon=True)
      self._thread.start()

  @property
  def freshness_ready(self) -> bool:
    return self.tracker.ready

  def set_control(self, enabled: bool, lat_active: bool, target_angle_deg: float,
                  long_active: bool = False, accel: float = 0.0,
                  set_speed_kph: float = 0.0) -> None:
    with self._cv:
      was_enabled = self.control_enabled
      self.control_enabled = bool(enabled)
      self.control_lat_active = self.control_enabled and bool(lat_active)
      self.control_target_angle_raw = target_angle_deg_to_raw(float(target_angle_deg))
      self.control_long_active = self.control_enabled and bool(long_active)
      self.control_accel = float(accel) if self.control_long_active else 0.0
      self.control_set_speed_kph = float(set_speed_kph)
      if was_enabled and not self.control_enabled:
        self._release_control_locked()
      elif not was_enabled and self.control_enabled:
        self._maybe_arm_locked()

  def authority_unavailable(self) -> bool:
    with self._cv:
      # Signing the first host generation is expected and should not surface as
      # a steering-unavailable warning. A rejected first frame clears
      # arm_pending and is reported normally on the next state update.
      return self.control_enabled and not self.active and not self.arm_pending

  def longitudinal_authority_unavailable(self) -> bool:
    with self._cv:
      return self.control_enabled and not self.active and not self.arm_pending

  def _record_failure_locked(self, reason: str) -> None:
    self.last_failure_reason = reason
    cloudlog.event("toyota_f33_request_plane_failure", reason=reason, active=self.active,
                   arm_pending=self.arm_pending, freshness_ready=self.tracker.ready,
                   native_index=self.native_index, error=True)

  def _invalidate_signing_locked(self) -> None:
    self.jobs.clear()
    self.inflight = None
    self._cv.notify_all()

  def _release_locked(self) -> None:
    if self.active or self.arm_pending:
      self._send_can([make_admin(False)])
    self.active = False
    self.arm_pending = False
    self.arm_host_frame = None

  def _release_control_locked(self) -> None:
    self._release_locked()
    self._invalidate_signing_locked()

  def _authority_failure_locked(self, reason: str) -> None:
    self._record_failure_locked(reason)
    self._release_control_locked()

  def _maybe_arm_locked(self) -> None:
    if self.active or self.arm_pending or not self.control_enabled or not self.tracker.ready or not self.can_valid:
      return
    self._send_can([make_admin(True)])
    self.arm_pending = True
    self.arm_host_frame = None

  def _make_native_event_locked(self, frame: bytes) -> NativeEvent | None:
    if len(frame) != 32 or self.sync_trip is None or self.sync_reset is None:
      return None
    fv4 = frame[28] >> 4
    epoch = resolve_epoch(self.sync_trip, self.sync_reset, fv4 & 0x3)
    if epoch is None:
      return None
    self.native_index += 1
    return NativeEvent(self.native_index, frame[26] & 0x3F, epoch[0], epoch[1], (fv4 >> 2) & 0x3)

  def _observe_sync_locked(self, data: bytes) -> None:
    try:
      self.sync_trip, self.sync_reset = decode_sync(data)
    except ValueError:
      pass

  def _queue_sign_locked(self, event: NativeEvent) -> bool:
    message_counter = self.tracker.message_counter
    if message_counter is None:
      self._authority_failure_locked("freshness_not_ready")
      return False
    if len(self.jobs) + int(self.inflight is not None) >= ORACLE_MAX_PENDING_GENERATIONS:
      self._authority_failure_locked("oracle_backlog")
      return False
    application = build_host_application(
      lat_active=self.control_lat_active,
      target_angle_raw=self.control_target_angle_raw,
      long_active=self.control_long_active,
      accel=self.control_accel,
      set_speed_kph=self.control_set_speed_kph,
      request_sequence=event.b26,
    )
    self.jobs.append(SignJob(event.index, application, event.reset_counter, message_counter, self._monotonic()))
    self._cv.notify_all()
    return True

  def _observe_native_locked(self, frame: bytes) -> None:
    event = self._make_native_event_locked(frame)
    if event is None or not self.can_valid:
      if self.control_enabled or self.active or self.arm_pending:
        self._authority_failure_locked("native_event_invalid")
      self.tracker.reset()
      return

    ready, lost = self.tracker.update(event)
    if lost:
      if self.control_enabled or self.active or self.arm_pending:
        self._record_failure_locked("freshness_lost")
      self._release_control_locked()
      return

    if not ready:
      return

    if self.arm_pending or self.active:
      if not self._queue_sign_locked(event):
        return

    self._maybe_arm_locked()

  def _observe_tx_echo_locked(self, address: int, data: bytes, src: int) -> None:
    if address == ADMIN_ADDR and self.arm_pending and data == make_admin(True).dat:
      if src == ADMIN_BUS + PANDA_REJECTED_OFFSET:
        self._authority_failure_locked("arm_admin_rejected")
      return
    if address != NATIVE_08A_ADDR:
      return
    if src == DOWNSTREAM_BUS + PANDA_RETURNED_OFFSET and self.arm_pending and data == self.arm_host_frame:
      self.active = True
      self.arm_pending = False
      self.arm_host_frame = None
    elif src == DOWNSTREAM_BUS + PANDA_REJECTED_OFFSET and self.arm_pending and data == self.arm_host_frame:
      self._authority_failure_locked("handoff_host_frame_rejected")
    elif src == DOWNSTREAM_BUS + PANDA_REJECTED_OFFSET and self.active:
      # A rejected actuation sample is an ordinary Panda safety outcome. Panda
      # keeps the authenticated request plane and the next freshness generation
      # recovers from the safety baseline; it is not an authority fault.
      cloudlog.event("toyota_f33_request_plane_tx_reject", native_index=self.native_index)

  def _retry_inflight_locked(self, now: float, reason: str) -> None:
    if self.inflight is None:
      return
    _, job = self.inflight
    self.inflight = None
    if now - job.queued_at > ORACLE_PUBLICATION_DEADLINE_S:
      self._authority_failure_locked("oracle_dead")
      return
    job.sent_at = None
    self.jobs.appendleft(job)
    cloudlog.event("toyota_f33_request_plane_retry", reason=reason, native_index=job.native_index,
                   attempts=job.attempts)
    self._cv.notify_all()

  def _observe_oracle_response_locked(self, data: bytes) -> None:
    if len(data) != 8 or data[0] != ORACLE_PRIVATE_SID:
      return
    seq, status = data[1], data[2]
    if not 1 <= seq <= ORACLE_SEQUENCE_MAX or data[3] != (seq ^ 0xFF):
      return
    if self.inflight is None or seq != self.inflight[0]:
      return
    _, job = self.inflight
    now = self._monotonic()
    if now - job.queued_at > ORACLE_PUBLICATION_DEADLINE_S:
      self._authority_failure_locked("oracle_dead")
      return
    if status != 0:
      self._retry_inflight_locked(now, "oracle_sign_status")
      return
    self.inflight = None
    frame = attach_authenticator(job.application, job.reset_counter, job.message_counter, data[4:8])
    if self.arm_pending and self.arm_host_frame is None:
      self.arm_host_frame = frame
    self._send_can([CanData(NATIVE_08A_ADDR, frame, DOWNSTREAM_BUS)])
    self._cv.notify_all()

  def _expire_locked(self, now: float) -> None:
    if self.inflight is None:
      return
    _, job = self.inflight
    if now - job.queued_at > ORACLE_PUBLICATION_DEADLINE_S:
      self._authority_failure_locked("oracle_dead")
    elif job.sent_at is not None and now - job.sent_at > ORACLE_RETRY_TIMEOUT_S:
      self._retry_inflight_locked(now, "oracle_response_timeout")

  def _next_job_locked(self, now: float) -> tuple[int, SignJob] | None:
    self._expire_locked(now)
    if self.inflight is not None or not self.jobs:
      return None
    if now - self.jobs[0].queued_at > ORACLE_PUBLICATION_DEADLINE_S:
      self._authority_failure_locked("oracle_dead")
      return None
    job = self.jobs.popleft()
    seq = self.next_oracle_seq
    self.next_oracle_seq = (seq % ORACLE_SEQUENCE_MAX) + 1
    job.sent_at = now
    job.attempts += 1
    self.inflight = (seq, job)
    return seq, job

  def _oracle_sender_loop(self) -> None:
    while True:
      with self._cv:
        if self._stop:
          return
        item = self._next_job_locked(self._monotonic())
        if item is None:
          self._cv.wait(timeout=0.002)
          continue
      seq, job = item
      self._send_can(build_oracle_transport(seq, job.application, job.message_counter, job.reset_counter))

  def update(self, can_list: list, CS: structs.CarState) -> None:
    with self._cv:
      self.can_valid = bool(CS.canValid)
      if not self.can_valid and (self.active or self.arm_pending):
        self._authority_failure_locked("can_invalid")
        self.tracker.reset()
      for _, packets in can_list:
        for address, dat, src in packets:
          address_i, src_i, data = int(address), int(src), bytes(dat)
          if src_i >= PANDA_RETURNED_OFFSET:
            self._observe_tx_echo_locked(address_i, data, src_i)
          elif src_i == SYNC_BUS and address_i == SECOC_SYNC_ADDR:
            self._observe_sync_locked(data)
          elif src_i == UPSTREAM_BUS and address_i == NATIVE_08A_ADDR:
            self._observe_native_locked(data)
          elif src_i == ORACLE_BUS and address_i == ORACLE_RESPONSE_ADDR:
            self._observe_oracle_response_locked(data)
      self._cv.notify_all()

  def shutdown(self) -> None:
    with self._cv:
      self._release_locked()
      self._stop = True
      self._cv.notify_all()
    if self._thread is not None:
      self._thread.join(timeout=1.0)
