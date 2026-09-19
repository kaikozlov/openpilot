"""Exact-F33 authenticated 0x08A request-plane replacement.

The FRC supplies each source generation and all non-lateral request fields. When
openpilot owns the request plane, the observed Camry lateral owner is replaced
with comma ID11 on that same source generation and the EPS RAM resident signs the
modified application. No future-generation prediction or host SecOC key is used.
"""
from __future__ import annotations

import struct
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from opendbc.car import structs
from opendbc.car.can_definitions import CanData
from opendbc.car.toyota.tss3 import target_angle_deg_to_raw
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

ORACLE_REQUEST_ADDR = 0x7A1
ORACLE_RESPONSE_ADDR = 0x7A9
ORACLE_BUS = 0
ORACLE_PRIVATE_SID = 0xC9
ORACLE_DOMAIN_LEN = 36
ORACLE_NSDU_LEN = 40
# Recorded road traffic: FF->FC max 33.7 ms; FC->private-response max 20.9 ms.
ORACLE_FC_TIMEOUT_S = 0.040
ORACLE_RESPONSE_TIMEOUT_S = 0.030

TSS3_LATERAL_SOURCE_IDS = (0, 4, 11, 18)  # No Request, LDA, LTA/LCA, SDG
TSS3_LTA_LCA_ID = 11
TSS3_LTA_ASSIST_GAIN_RAW = 100


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


def build_secoc_domain(application: bytes, trip_counter: int, reset_counter: int, message_counter: int) -> bytes:
  if len(application) != 28:
    raise ValueError("0x08A application must be 28 bytes")
  freshness = struct.pack(">HI", trip_counter,
                          (reset_counter << 12) | (message_counter << 4) | ((reset_counter & 0x3) << 2))
  return b"\x00\x8A" + application + freshness


def build_oracle_transport(seq: int, domain: bytes) -> tuple[CanData, list[CanData]]:
  if not 1 <= seq <= 0xFF:
    raise ValueError("oracle sequence must be 1..255")
  if len(domain) != ORACLE_DOMAIN_LEN or domain[:2] != b"\x00\x8A":
    raise ValueError("oracle domain must be exact 36-byte 0x008A domain")
  nsdu = bytes((ORACLE_PRIVATE_SID, ORACLE_PRIVATE_SID, seq)) + domain + bytes((seq ^ 0xFF,))
  if len(nsdu) != ORACLE_NSDU_LEN:
    raise AssertionError("oracle N-SDU geometry drift")
  ff = CanData(ORACLE_REQUEST_ADDR, bytes((0x10, ORACLE_NSDU_LEN)) + nsdu[:6], ORACLE_BUS)
  remaining = nsdu[6:]
  cfs = []
  for sn in range(1, 6):
    chunk, remaining = remaining[:7], remaining[7:]
    cfs.append(CanData(ORACLE_REQUEST_ADDR, bytes((0x20 | sn,)) + chunk + bytes(7 - len(chunk)), ORACLE_BUS))
  if remaining:
    raise AssertionError("oracle CF geometry drift")
  return ff, cfs


def build_signed_frame(application: bytes, reset_counter: int, message_counter: int, cmac4: bytes) -> bytes:
  if len(application) != 28 or len(cmac4) != 4:
    raise ValueError("invalid signed-frame geometry")
  fv4 = ((message_counter & 0x3) << 2) | (reset_counter & 0x3)
  mac28 = int.from_bytes(cmac4, "big") >> 4
  return application + ((fv4 << 28) | mac28).to_bytes(4, "big")


def build_id11_application(native_application: bytes, target_angle_raw: int) -> bytes:
  if len(native_application) != 28:
    raise ValueError("native 0x08A application must be 28 bytes")
  native_id = native_application[21] & 0x3F
  if native_id not in TSS3_LATERAL_SOURCE_IDS:
    raise ValueError(f"unsupported native lateral request ID {native_id}")
  application = bytearray(native_application)
  application[18:20] = target_angle_raw.to_bytes(2, "big", signed=True)
  application[21] = (application[21] & 0xC0) | TSS3_LTA_LCA_ID
  if native_id != TSS3_LTA_LCA_ID:
    application[24] = TSS3_LTA_ASSIST_GAIN_RAW
  return bytes(application)


@dataclass(frozen=True)
class NativeEvent:
  index: int
  frame: bytes
  application: bytes
  b26: int
  trip_counter: int
  reset_counter: int
  message_low2: int

  @property
  def target_id(self) -> int:
    return self.application[21] & 0x3F


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
  domain: bytes
  ff_sent_at: float | None = None
  cfs_sent_at: float | None = None


class ToyotaTss3RequestProxy:
  """Minimal asynchronous signer/forwarding adapter for exact-F33 0x08A."""

  def __init__(self, send_can: SendCan, *, start_thread: bool = True, monotonic=time.monotonic):
    self._send_can = send_can
    self._monotonic = monotonic
    self._cv = threading.Condition(threading.RLock())
    self._stop = False
    self._thread: threading.Thread | None = None

    self.can_valid = False
    self.control_lat_active = False
    self.control_target_angle_raw = 0
    self.sync_trip: int | None = None
    self.sync_reset: int | None = None
    self.native_index = 0
    self.tracker = NativeFreshnessTracker()

    self.jobs: deque[SignJob] = deque()
    self.transport: tuple[int, SignJob] | None = None  # FF sent, waiting for EPS FC
    self.inflight: dict[int, SignJob] = {}             # CFs sent, waiting for private response
    self.next_oracle_seq = 1

    self.active = False
    self.arm_pending = False
    self.arm_clone_frame: bytes | None = None
    self.handoff_completed = False

    self.pending_outputs: dict[int, bytes | None] = {}
    self.next_output_index: int | None = None

    self.last_failure_reason = ""

    if start_thread:
      self._thread = threading.Thread(target=self._oracle_sender_loop, name="tss3_08a_oracle", daemon=True)
      self._thread.start()

  @property
  def freshness_ready(self) -> bool:
    return self.tracker.ready

  def set_control(self, lat_active: bool, target_angle_deg: float) -> None:
    with self._cv:
      was_active = self.control_lat_active
      self.control_lat_active = bool(lat_active)
      self.control_target_angle_raw = target_angle_deg_to_raw(float(target_angle_deg))
      if was_active and not self.control_lat_active:
        self._release_control_locked()
      elif not was_active and self.control_lat_active:
        self._maybe_arm_locked()

  def consume_handoff_completed(self) -> bool:
    with self._cv:
      completed = self.handoff_completed
      self.handoff_completed = False
      return completed

  def authority_unavailable(self) -> bool:
    with self._cv:
      return self.control_lat_active and not self.active

  def _record_failure_locked(self, reason: str) -> None:
    self.last_failure_reason = reason
    cloudlog.event("toyota_f33_request_plane_failure", reason=reason, active=self.active,
                   arm_pending=self.arm_pending, freshness_ready=self.tracker.ready,
                   native_index=self.native_index, error=True)

  def _invalidate_signing_locked(self) -> None:
    self.jobs.clear()
    self.transport = None
    self.inflight.clear()
    self.pending_outputs.clear()
    self.next_output_index = None
    self._cv.notify_all()

  def _release_locked(self) -> None:
    if self.active or self.arm_pending:
      self._send_can([make_admin(False)])
    self.active = False
    self.arm_pending = False
    self.arm_clone_frame = None
    self.handoff_completed = False

  def _release_control_locked(self) -> None:
    self._release_locked()
    self._invalidate_signing_locked()

  def _authority_failure_locked(self, reason: str) -> None:
    self._record_failure_locked(reason)
    self._release_control_locked()

  def _maybe_arm_locked(self) -> None:
    if self.active or self.arm_pending or not self.control_lat_active or not self.tracker.ready or not self.can_valid:
      return
    self._send_can([make_admin(True)])
    self.arm_pending = True
    self.arm_clone_frame = None

  def _make_native_event_locked(self, frame: bytes) -> NativeEvent | None:
    if len(frame) != 32 or self.sync_trip is None or self.sync_reset is None:
      return None
    fv4 = frame[28] >> 4
    epoch = resolve_epoch(self.sync_trip, self.sync_reset, fv4 & 0x3)
    if epoch is None:
      return None
    self.native_index += 1
    return NativeEvent(self.native_index, frame, frame[:28], frame[26] & 0x3F,
                       epoch[0], epoch[1], (fv4 >> 2) & 0x3)

  def _observe_sync_locked(self, data: bytes) -> None:
    try:
      self.sync_trip, self.sync_reset = decode_sync(data)
    except ValueError:
      pass

  def _queue_sign_locked(self, event: NativeEvent) -> None:
    if event.target_id not in TSS3_LATERAL_SOURCE_IDS:
      self._authority_failure_locked("unsupported_native_lateral_id")
      return
    message_counter = self.tracker.message_counter
    if message_counter is None:
      self._authority_failure_locked("freshness_not_ready")
      return
    application = build_id11_application(event.application, self.control_target_angle_raw)
    if self.next_output_index is None:
      self.next_output_index = event.index
    self.pending_outputs[event.index] = None
    self.jobs.append(SignJob(
      event.index, application, event.reset_counter, message_counter,
      build_secoc_domain(application, event.trip_counter, event.reset_counter, message_counter),
    ))
    self._cv.notify_all()

  def _observe_native_locked(self, frame: bytes) -> None:
    event = self._make_native_event_locked(frame)
    if event is None or not self.can_valid:
      if self.control_lat_active or self.active or self.arm_pending:
        self._authority_failure_locked("native_event_invalid")
      self.tracker.reset()
      return

    ready, lost = self.tracker.update(event)
    if lost:
      if self.control_lat_active or self.active or self.arm_pending:
        self._record_failure_locked("freshness_lost")
      self._release_control_locked()
      return

    if not ready:
      return

    if self.arm_pending:
      if self.arm_clone_frame is not None:
        self._authority_failure_locked("handoff_source_overrun")
        return
      self.arm_clone_frame = event.frame
      self.next_output_index = event.index + 1
      self._send_can([CanData(NATIVE_08A_ADDR, event.frame, DOWNSTREAM_BUS)])
    elif self.active:
      self._queue_sign_locked(event)

    self._maybe_arm_locked()

  def _observe_tx_echo_locked(self, address: int, data: bytes, src: int) -> None:
    if address == ADMIN_ADDR and self.arm_pending and data == make_admin(True).dat:
      if src == ADMIN_BUS + PANDA_REJECTED_OFFSET:
        self._authority_failure_locked("arm_admin_rejected")
      return
    if address != NATIVE_08A_ADDR:
      return
    if src == DOWNSTREAM_BUS + PANDA_RETURNED_OFFSET and self.arm_pending and data == self.arm_clone_frame:
      self.active = True
      self.arm_pending = False
      self.handoff_completed = True
      self.arm_clone_frame = None
    elif src == DOWNSTREAM_BUS + PANDA_REJECTED_OFFSET and self.arm_pending and data == self.arm_clone_frame:
      self._authority_failure_locked("handoff_clone_rejected")
    elif src == DOWNSTREAM_BUS + PANDA_REJECTED_OFFSET and self.active:
      cloudlog.event("toyota_f33_request_plane_tx_reject", native_index=self.native_index, error=True)
      self._release_control_locked()

  def _flush_outputs_locked(self) -> None:
    if self.next_output_index is None:
      return
    out = []
    while self.next_output_index in self.pending_outputs and self.pending_outputs[self.next_output_index] is not None:
      out.append(CanData(NATIVE_08A_ADDR, self.pending_outputs.pop(self.next_output_index), DOWNSTREAM_BUS))
      self.next_output_index += 1
    if out:
      self._send_can(out)

  def _observe_oracle_response_locked(self, data: bytes) -> None:
    if len(data) != 8:
      return
    if data[:3] == bytes((0x30, 0x00, ORACLE_NSDU_LEN)):
      if self.transport is None:
        return
      seq, job = self.transport
      self.transport = None
      _, cfs = build_oracle_transport(seq, job.domain)
      job.cfs_sent_at = self._monotonic()
      self.inflight[seq] = job
      self._send_can(cfs)
      self._cv.notify_all()
      return
    if data[0] != 0x07 or data[1] != ORACLE_PRIVATE_SID:
      return
    seq, status = data[2], data[3]
    job = self.inflight.pop(seq, None)
    if job is None:
      return
    if status != 0:
      self._authority_failure_locked("oracle_sign_failure")
      return
    if job.native_index not in self.pending_outputs:
      return
    self.pending_outputs[job.native_index] = build_signed_frame(job.application, job.reset_counter, job.message_counter, data[4:8])
    self._flush_outputs_locked()
    self._cv.notify_all()

  def _alloc_seq_locked(self) -> int:
    used = set(self.inflight)
    if self.transport is not None:
      used.add(self.transport[0])
    for _ in range(255):
      seq = self.next_oracle_seq
      self.next_oracle_seq = (seq % 255) + 1
      if seq not in used:
        return seq
    raise RuntimeError("oracle sequence space exhausted")

  def _expire_locked(self, now: float) -> None:
    if self.transport is not None:
      _, job = self.transport
      if job.ff_sent_at is not None and now - job.ff_sent_at > ORACLE_FC_TIMEOUT_S:
        self._authority_failure_locked("oracle_fc_timeout")
        return
    for job in tuple(self.inflight.values()):
      if job.cfs_sent_at is not None and now - job.cfs_sent_at > ORACLE_RESPONSE_TIMEOUT_S:
        self._authority_failure_locked("oracle_response_timeout")
        return

  def _next_job_locked(self, now: float) -> tuple[int, SignJob] | None:
    self._expire_locked(now)
    if self.transport is not None:
      return None
    if not self.jobs:
      return None
    job = self.jobs.popleft()
    seq = self._alloc_seq_locked()
    job.ff_sent_at = now
    self.transport = (seq, job)
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
      ff, _ = build_oracle_transport(seq, job.domain)
      self._send_can([ff])

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
