"""Exact-F33 authenticated comma-owned 0x08A request plane.

Openpilot supplies only application semantics and publication cadence. The EPS
RAM resident owns Toyota freshness, signs each application, and returns the
finished FV4/MAC28 trailer. Panda authorizes and bounds the resulting frame.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from opendbc.car import structs
from opendbc.car.can_definitions import CanData
from opendbc.car.toyota.tss3 import build_host_application, target_angle_deg_to_raw
from opendbc.car.toyota.values import CAR, ToyotaSafetyFlags
from openpilot.common.swaglog import cloudlog

NATIVE_08A_ADDR = 0x08A
ADMIN_ADDR = 0x777
DOWNSTREAM_BUS = 0
ADMIN_BUS = 1
PANDA_RETURNED_OFFSET = 0x80
PANDA_REJECTED_OFFSET = 0xC0
SendCan = Callable[[list[CanData]], None]

ORACLE_REQUEST_ADDR = 0x777
ORACLE_RESPONSE_ADDR = 0x7A9
ORACLE_BUS = 0
ORACLE_PRIVATE_SID = 0xC9
ORACLE_SEQUENCE_MAX = 0x1F
ORACLE_MAX_PENDING_GENERATIONS = 8
ORACLE_PUBLICATION_PERIOD_S = 0.025
# The measured raw-mailbox signer latency remains comfortably below this. A
# lost response is retried with the same application; the EPS simply returns a
# newly fresh trailer. Panda's 100 ms forwarding watchdog is the final bound.
ORACLE_RETRY_TIMEOUT_S = 0.050
ORACLE_PUBLICATION_DEADLINE_S = 0.090


def make_admin(arm: bool) -> CanData:
  return CanData(ADMIN_ADDR, bytes((7, 0xC9, 0xA8, int(arm), 0, 0, 0, 0)), ADMIN_BUS)


def request_plane_enabled(CP: structs.CarParams) -> bool:
  return (CP.carFingerprint == CAR.TOYOTA_CAMRY_TSS3 and not CP.passive and bool(CP.safetyConfigs) and
          bool(CP.safetyConfigs[0].safetyParam & ToyotaSafetyFlags.TSS3_08A_HOST.value))


def build_oracle_transport(seq: int, application: bytes) -> list[CanData]:
  """Carry one 28-byte application through the EPS raw diagnostic ring."""
  if not 1 <= seq <= ORACLE_SEQUENCE_MAX:
    raise ValueError(f"oracle sequence must be 1..{ORACLE_SEQUENCE_MAX}")
  if len(application) != 28:
    raise ValueError("oracle application must be exactly 28 bytes")

  stream = application + b"\0\0"
  return [CanData(ORACLE_REQUEST_ADDR,
                  bytes((0xC8, (fragment << 5) | seq)) + stream[fragment * 5:(fragment + 1) * 5] + b"\0",
                  ORACLE_BUS) for fragment in range(6)]


@dataclass
class SignJob:
  publication_index: int
  application: bytes
  queued_at: float
  sent_at: float | None = None
  attempts: int = 0


class ToyotaTss3RequestProxy:
  """Asynchronous application-to-authenticated-0x08A adapter."""

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

    self.jobs: deque[SignJob] = deque()
    self.inflight: tuple[int, SignJob] | None = None
    self.next_oracle_seq = 1
    self.next_request_sequence = 0
    self.next_publication_index = 1
    self.next_publication_at: float | None = None

    self.active = False
    self.arm_pending = False
    self.arm_host_frame: bytes | None = None
    self.last_failure_reason = ""

    if start_thread:
      self._thread = threading.Thread(target=self._oracle_sender_loop, name="tss3_08a_oracle", daemon=True)
      self._thread.start()

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
      elif self.control_enabled:
        if not was_enabled:
          self.next_request_sequence = 0
        self._maybe_arm_locked()
      self._cv.notify_all()

  def authority_unavailable(self) -> bool:
    with self._cv:
      return self.control_enabled and not self.active and not self.arm_pending

  def longitudinal_authority_unavailable(self) -> bool:
    return self.authority_unavailable()

  def _record_failure_locked(self, reason: str) -> None:
    self.last_failure_reason = reason
    cloudlog.event("toyota_f33_request_plane_failure", reason=reason, active=self.active,
                   arm_pending=self.arm_pending, publication_index=self.next_publication_index, error=True)

  def _invalidate_signing_locked(self) -> None:
    self.jobs.clear()
    self.inflight = None
    self.next_publication_at = None
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
    if self.active or self.arm_pending or not self.control_enabled or not self.can_valid:
      return
    self._send_can([make_admin(True)])
    self.arm_pending = True
    self.arm_host_frame = None
    self.next_publication_at = self._monotonic()

  def _schedule_due_locked(self, now: float) -> None:
    if not (self.arm_pending or self.active) or self.next_publication_at is None:
      return

    while now >= self.next_publication_at:
      if len(self.jobs) + int(self.inflight is not None) >= ORACLE_MAX_PENDING_GENERATIONS:
        self._authority_failure_locked("oracle_backlog")
        return
      application = build_host_application(
        lat_active=self.control_lat_active,
        target_angle_raw=self.control_target_angle_raw,
        long_active=self.control_long_active,
        accel=self.control_accel,
        set_speed_kph=self.control_set_speed_kph,
        request_sequence=self.next_request_sequence,
      )
      self.jobs.append(SignJob(self.next_publication_index, application, self.next_publication_at))
      self.next_publication_index += 1
      self.next_request_sequence = (self.next_request_sequence + 1) & 0x3F
      self.next_publication_at += ORACLE_PUBLICATION_PERIOD_S

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
      cloudlog.event("toyota_f33_request_plane_tx_reject", publication_index=self.next_publication_index)

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
    cloudlog.event("toyota_f33_request_plane_retry", reason=reason, publication_index=job.publication_index,
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
    frame = job.application + data[4:8]
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
    self._schedule_due_locked(now)
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
      self._send_can(build_oracle_transport(seq, job.application))

  def update(self, can_list: list, CS: structs.CarState) -> None:
    with self._cv:
      self.can_valid = bool(CS.canValid)
      if not self.can_valid and (self.active or self.arm_pending):
        self._authority_failure_locked("can_invalid")
      self._maybe_arm_locked()
      for _, packets in can_list:
        for address, dat, src in packets:
          address_i, src_i, data = int(address), int(src), bytes(dat)
          if src_i >= PANDA_RETURNED_OFFSET:
            self._observe_tx_echo_locked(address_i, data, src_i)
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
