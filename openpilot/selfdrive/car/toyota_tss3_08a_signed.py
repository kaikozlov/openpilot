"""Development-only exact-F33 signed ID0 0x08A replacement.

This is phase 1 after the transparent exact-frame proxy. It remains Park/stationary
and Target Lateral ID 0 only. The FRC stays alive upstream as the authoritative
application/freshness-phase oracle; Panda blocks its 0x08A only after a future
signed replacement is ready.

The host never learns the TSK key. It asks the already-qualified EPS RAM resident
to run ICU-S command 5 / selector 4 over the ordinary P5 domain and receives only
CMAC[0:4] on 0x7A9.
"""
from __future__ import annotations

import struct
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Literal

from opendbc.car import structs
from opendbc.car.can_definitions import CanData
from opendbc.car.toyota.values import CAR, ToyotaSafetyFlags
from openpilot.selfdrive.car.toyota_tss3_08a import (
  ADMIN_ADDR,
  ADMIN_BUS,
  DOWNSTREAM_BUS,
  NATIVE_08A_ADDR,
  PANDA_REJECTED_OFFSET,
  PANDA_RETURNED_OFFSET,
  SECOC_SYNC_ADDR,
  STABLE_NATIVE_FRAMES,
  UPSTREAM_BUS,
  SendCan,
  decode_sync,
  make_admin,
)

ORACLE_REQUEST_ADDR = 0x7A1
ORACLE_RESPONSE_ADDR = 0x7A9
ORACLE_BUS = 1
ORACLE_PRIVATE_SID = 0xC9
ORACLE_DOMAIN_LEN = 36
ORACLE_NSDU_LEN = 40
ORACLE_PRE_CF_DELAY_S = 0.005
ORACLE_PERIOD_S = 0.025
ORACLE_TIMEOUT_S = 0.12
ORACLE_MAX_INFLIGHT = 4
ORACLE_FAILURE_COOLDOWN_S = 2.0
SIGNED_LOOKAHEAD = 2
MAX_NATIVE_HISTORY = 256
MAX_NATIVE_GAP = 8

GearShifter = structs.CarState.GearShifter
JobKind = Literal["recover", "verify", "sign"]


def enable_signed_in_car_params(CP: structs.CarParams, *, requested: bool, is_release: bool) -> bool:
  enabled = requested and not is_release and CP.carFingerprint == CAR.TOYOTA_CAMRY_TSS3 and not CP.passive
  if enabled:
    CP.safetyConfigs[0].safetyParam |= (ToyotaSafetyFlags.TSS3_08A_HOST.value |
                                        ToyotaSafetyFlags.TSS3_08A_SIGNED.value)
  return enabled


def shift_reset_epoch(trip_counter: int, reset_counter: int, delta: int) -> tuple[int, int]:
  packed = (((trip_counter << 20) | reset_counter) + delta) & ((1 << 36) - 1)
  return packed >> 20, packed & ((1 << 20) - 1)


def resolve_epoch(sync_trip: int, sync_reset: int, reset_low2: int) -> tuple[int, int] | None:
  """Resolve the nearest ordinary-P5 reset epoch compatible with transmitted FV4."""
  for delta in (0, -1, 1, -2, 2):
    trip, reset = shift_reset_epoch(sync_trip, sync_reset, delta)
    if (reset & 0x3) == reset_low2:
      return trip, reset
  return None


def build_secoc_domain(application: bytes, trip_counter: int, reset_counter: int, message_counter: int) -> bytes:
  if len(application) != 28:
    raise ValueError("0x08A application must be 28 bytes")
  if not 0 <= trip_counter < (1 << 16):
    raise ValueError("trip counter must be 16-bit")
  if not 0 <= reset_counter < (1 << 20):
    raise ValueError("reset counter must be 20-bit")
  if not 0 <= message_counter < (1 << 8):
    raise ValueError("message counter must be 8-bit")
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
  ff = bytes((0x10, ORACLE_NSDU_LEN)) + nsdu[:6]
  remaining = nsdu[6:]
  sn = 1
  cfs: list[CanData] = []
  while remaining:
    chunk, remaining = remaining[:7], remaining[7:]
    frame = bytes((0x20 | (sn & 0xF),)) + chunk + bytes(7 - len(chunk))
    cfs.append(CanData(ORACLE_REQUEST_ADDR, frame, ORACLE_BUS))
    sn += 1
  if len(cfs) != 5:
    raise AssertionError("oracle CF geometry drift")
  return CanData(ORACLE_REQUEST_ADDR, ff, ORACLE_BUS), cfs


def mac28_hex_from_native(frame: bytes) -> str:
  if len(frame) != 32:
    raise ValueError("native 0x08A must be 32 bytes")
  return frame[28:32].hex()[1:]


def mac28_hex_from_cmac4(cmac4: bytes) -> str:
  if len(cmac4) != 4:
    raise ValueError("oracle CMAC prefix must be 4 bytes")
  return cmac4.hex()[:7]


def build_signed_frame(application: bytes, reset_counter: int, message_counter: int, cmac4: bytes) -> bytes:
  if len(application) != 28 or len(cmac4) != 4:
    raise ValueError("invalid signed-frame geometry")
  fv4 = ((message_counter & 0x3) << 2) | (reset_counter & 0x3)
  mac28 = int.from_bytes(cmac4, "big") >> 4
  trailer = ((fv4 << 28) | mac28).to_bytes(4, "big")
  return application + trailer


@dataclass(frozen=True)
class NativeEvent:
  index: int
  frame: bytes
  application: bytes
  b26: int
  trip_counter: int
  reset_counter: int
  message_low2: int
  mac28_hex: str


class NativeFreshnessTracker:
  def __init__(self) -> None:
    self.event: NativeEvent | None = None
    self.message_counter: int | None = None

  def seed(self, event: NativeEvent, message_counter: int) -> bool:
    if (message_counter & 0x3) != event.message_low2:
      return False
    self.event = event
    self.message_counter = message_counter
    return True

  def update(self, event: NativeEvent) -> tuple[bool, bool]:
    """Return (valid, epoch_changed)."""
    if self.event is None or self.message_counter is None:
      return False, False
    prev = self.event
    epoch_changed = (event.trip_counter, event.reset_counter) != (prev.trip_counter, prev.reset_counter)
    if epoch_changed:
      message = event.message_low2
    else:
      delta = (event.b26 - prev.b26) & 0x3F
      if not 1 <= delta <= MAX_NATIVE_GAP:
        return False, False
      message = self.message_counter + delta
      if message > 0xFF or (message & 0x3) != event.message_low2:
        return False, False
    self.event = event
    self.message_counter = message
    return True, epoch_changed


@dataclass
class OracleJob:
  kind: JobKind
  generation: int
  domain: bytes
  expected_mac28: str | None = None
  native_index: int | None = None
  candidate_message: int | None = None
  application: bytes | None = None
  trip_counter: int | None = None
  reset_counter: int | None = None
  message_counter: int | None = None
  b26: int | None = None
  sent_at: float | None = None

  @property
  def target_key(self) -> tuple[int, int, int, int] | None:
    if None in (self.trip_counter, self.reset_counter, self.message_counter, self.b26):
      return None
    return (int(self.trip_counter), int(self.reset_counter), int(self.message_counter), int(self.b26))


class ToyotaTss3SignedId0Proxy:
  """Stationary ID0 signer with two-generation lookahead and fail-open ownership."""

  def __init__(self, send_can: SendCan, *, start_thread: bool = True,
               monotonic=time.monotonic, sleep=time.sleep):
    self._send_can = send_can
    self._monotonic = monotonic
    self._sleep = sleep
    self._lock = threading.RLock()
    self._cv = threading.Condition(self._lock)
    self._stop = False
    self._thread: threading.Thread | None = None

    self.stationary_park = False
    self.sync_trip: int | None = None
    self.sync_reset: int | None = None
    self.native_index = 0
    self.history: deque[NativeEvent] = deque(maxlen=MAX_NATIVE_HISTORY)
    self.last_native_b26: int | None = None
    self.stable_native_frames = 0

    self.tracker = NativeFreshnessTracker()
    self.qualified = False
    self.recovery_active = False
    self.recovery_sample_index: int | None = None
    self.recovery_remaining = 0
    self.state_generation = 0
    self.cooldown_until = 0.0

    self.jobs: deque[OracleJob] = deque()
    self.inflight: dict[int, OracleJob] = {}
    self.next_oracle_seq = 1
    self.next_oracle_send_at = 0.0
    self.oracle_failures = 0
    self.pending_targets: set[tuple[int, int, int, int]] = set()
    self.signed_cache: dict[tuple[int, int, int, int], bytes] = {}

    self.active = False
    self.arm_pending = False
    self.arm_pending_reset: int | None = None
    self.arm_admin_data: bytes | None = None
    self.arm_accepted = False

    self.arm_count = 0
    self.signed_tx_count = 0
    self.transparent_fallback_count = 0
    self.release_count = 0
    self.oracle_response_count = 0
    self.oracle_timeout_count = 0
    self.recovery_count = 0
    self.verification_count = 0

    if start_thread:
      self._thread = threading.Thread(target=self._oracle_sender_loop, name="tss3_08a_oracle", daemon=True)
      self._thread.start()

  @staticmethod
  def _stationary_park(CS: structs.CarState) -> bool:
    return bool(CS.canValid and CS.standstill and CS.gearShifter == GearShifter.park)

  def _clear_signed_state_locked(self) -> None:
    self.state_generation += 1
    self.jobs.clear()
    self.pending_targets.clear()
    self.signed_cache.clear()
    self.qualified = False
    self.recovery_active = False
    self.recovery_sample_index = None
    self.recovery_remaining = 0
    self._cv.notify_all()

  def _release_locked(self, *, send_admin: bool = True) -> None:
    if send_admin and (self.active or self.arm_pending):
      self._send_can([make_admin(False)])
      self.release_count += 1
    self.active = False
    self.arm_pending = False
    self.arm_pending_reset = None
    self.arm_admin_data = None
    self.arm_accepted = False

  def _fail_open_locked(self) -> None:
    self._release_locked()
    self._clear_signed_state_locked()
    self.tracker = NativeFreshnessTracker()
    self.stable_native_frames = 0
    self.last_native_b26 = None

  def _queue_job_locked(self, job: OracleJob, *, front: bool = False) -> None:
    if front:
      self.jobs.appendleft(job)
    else:
      self.jobs.append(job)
    self._cv.notify_all()

  def _start_recovery_locked(self, event: NativeEvent) -> None:
    if self._monotonic() < self.cooldown_until or self.recovery_active:
      return
    self._clear_signed_state_locked()
    self.recovery_active = True
    self.recovery_sample_index = event.index
    self.recovery_remaining = 64
    self.recovery_count += 1
    generation = self.state_generation
    for message in range(event.message_low2, 0x100, 4):
      self._queue_job_locked(OracleJob(
        kind="recover",
        generation=generation,
        domain=build_secoc_domain(event.application, event.trip_counter, event.reset_counter, message),
        expected_mac28=event.mac28_hex,
        native_index=event.index,
        candidate_message=message,
      ))

  def _event_by_index_locked(self, index: int) -> NativeEvent | None:
    return next((event for event in self.history if event.index == index), None)

  def _seed_tracker_from_recovery_locked(self, sample_index: int, message_counter: int) -> bool:
    sample = self._event_by_index_locked(sample_index)
    if sample is None:
      return False
    tracker = NativeFreshnessTracker()
    if not tracker.seed(sample, message_counter):
      return False
    for event in self.history:
      if event.index <= sample_index:
        continue
      valid, _ = tracker.update(event)
      if not valid:
        return False
    self.tracker = tracker
    self.state_generation += 1  # cancel remaining recovery candidates
    self.jobs.clear()
    self.pending_targets.clear()
    self.signed_cache.clear()
    self.recovery_active = False
    self.recovery_sample_index = None
    self.recovery_remaining = 0
    self.qualified = False
    if tracker.event is not None and tracker.message_counter is not None:
      self._queue_verify_locked(tracker.event, tracker.message_counter)
    return True

  def _queue_verify_locked(self, event: NativeEvent, message_counter: int) -> None:
    self.verification_count += 1
    self._queue_job_locked(OracleJob(
      kind="verify",
      generation=self.state_generation,
      domain=build_secoc_domain(event.application, event.trip_counter, event.reset_counter, message_counter),
      expected_mac28=event.mac28_hex,
      native_index=event.index,
      candidate_message=message_counter,
    ), front=True)

  def _schedule_future_sign_locked(self, event: NativeEvent, message_counter: int) -> None:
    target_message = message_counter + SIGNED_LOOKAHEAD
    if target_message > 0xFF:
      return
    target_b26 = (event.b26 + SIGNED_LOOKAHEAD) & 0x3F
    target_key = (event.trip_counter, event.reset_counter, target_message, target_b26)
    if target_key in self.pending_targets or target_key in self.signed_cache:
      return
    application = bytearray(event.application)
    application[26] = (application[26] & 0xC0) | target_b26
    app = bytes(application)
    self.pending_targets.add(target_key)
    self._queue_job_locked(OracleJob(
      kind="sign",
      generation=self.state_generation,
      domain=build_secoc_domain(app, event.trip_counter, event.reset_counter, target_message),
      application=app,
      trip_counter=event.trip_counter,
      reset_counter=event.reset_counter,
      message_counter=target_message,
      b26=target_b26,
    ))

  def _maybe_arm_locked(self, event: NativeEvent, message_counter: int) -> None:
    if self.active or self.arm_pending or not self.qualified or self.stable_native_frames < STABLE_NATIVE_FRAMES:
      return
    if not self.signed_cache:
      return
    admin = make_admin(True)
    self._send_can([admin])
    self.arm_pending = True
    self.arm_pending_reset = event.reset_counter
    self.arm_admin_data = admin.dat
    self.arm_accepted = False

  def _make_native_event_locked(self, frame: bytes) -> NativeEvent | None:
    if len(frame) != 32 or self.sync_trip is None or self.sync_reset is None:
      return None
    if (frame[21] & 0x3F) != 0:
      return None
    fv4 = frame[28] >> 4
    epoch = resolve_epoch(self.sync_trip, self.sync_reset, fv4 & 0x3)
    if epoch is None:
      return None
    trip, reset = epoch
    self.native_index += 1
    return NativeEvent(
      index=self.native_index,
      frame=frame,
      application=frame[:28],
      b26=frame[26] & 0x3F,
      trip_counter=trip,
      reset_counter=reset,
      message_low2=(fv4 >> 2) & 0x3,
      mac28_hex=mac28_hex_from_native(frame),
    )

  def _observe_sync_locked(self, data: bytes) -> None:
    try:
      trip, reset = decode_sync(data)
    except ValueError:
      return
    changed = self.sync_trip is not None and (trip, reset) != (self.sync_trip, self.sync_reset)
    self.sync_trip, self.sync_reset = trip, reset
    if changed and (self.active or self.arm_pending):
      # Panda safety independently drops ownership on reset-counter changes.
      self._release_locked(send_admin=False)

  def _observe_native_locked(self, frame: bytes) -> None:
    event = self._make_native_event_locked(frame)
    if event is None or not self.stationary_park:
      self._fail_open_locked()
      return

    if self.last_native_b26 is not None and event.b26 == ((self.last_native_b26 + 1) & 0x3F):
      self.stable_native_frames += 1
    else:
      self.stable_native_frames = 1
    self.last_native_b26 = event.b26
    self.history.append(event)

    if self.tracker.event is None or self.tracker.message_counter is None:
      if self.stable_native_frames >= STABLE_NATIVE_FRAMES:
        self._start_recovery_locked(event)
      return

    prev_epoch = (self.tracker.event.trip_counter, self.tracker.event.reset_counter)
    valid, epoch_changed = self.tracker.update(event)
    if not valid or self.tracker.message_counter is None:
      self.tracker = NativeFreshnessTracker()
      self._start_recovery_locked(event)
      return

    message_counter = self.tracker.message_counter
    if epoch_changed or (event.trip_counter, event.reset_counter) != prev_epoch:
      self._release_locked(send_admin=False)
      self._clear_signed_state_locked()
      self._queue_verify_locked(event, message_counter)
      return

    if self.arm_pending or self.active:
      key = (event.trip_counter, event.reset_counter, message_counter, event.b26)
      replacement = self.signed_cache.pop(key, None)
      if replacement is not None:
        self._send_can([CanData(NATIVE_08A_ADDR, replacement, DOWNSTREAM_BUS)])
        if self.active:
          self.signed_tx_count += 1
      else:
        # During handoff and any signing miss, offer the exact OEM frame. Safety
        # drops it while stock owns the path and accepts it once ownership is
        # active, preserving continuity without predicting the handoff B26.
        self._send_can([CanData(NATIVE_08A_ADDR, event.frame, DOWNSTREAM_BUS)])
        if self.active:
          self.transparent_fallback_count += 1

    if self.qualified:
      self._schedule_future_sign_locked(event, message_counter)
      self._maybe_arm_locked(event, message_counter)

  def _observe_tx_echo_locked(self, address: int, data: bytes, src: int) -> None:
    if address == ADMIN_ADDR and self.arm_pending and data == self.arm_admin_data:
      if src == ADMIN_BUS + PANDA_RETURNED_OFFSET:
        tracker_reset = self.tracker.event.reset_counter if self.tracker.event is not None else None
        if self.arm_pending_reset != tracker_reset:
          self._send_can([make_admin(False)])
          self.release_count += 1
          self._release_locked(send_admin=False)
        else:
          self.arm_accepted = True
      elif src == ADMIN_BUS + PANDA_REJECTED_OFFSET:
        self.arm_pending = False
        self.arm_pending_reset = None
        self.arm_admin_data = None
        self.arm_accepted = False
      return

    if address == NATIVE_08A_ADDR:
      if src == DOWNSTREAM_BUS + PANDA_RETURNED_OFFSET and self.arm_pending and self.arm_accepted:
        self.active = True
        self.arm_pending = False
        self.arm_pending_reset = None
        self.arm_admin_data = None
        self.arm_accepted = False
        self.arm_count += 1
      elif src == DOWNSTREAM_BUS + PANDA_REJECTED_OFFSET and self.active:
        self._fail_open_locked()

  def _observe_oracle_response_locked(self, data: bytes) -> None:
    if len(data) != 8 or data[0] != 0x07 or data[1] != ORACLE_PRIVATE_SID:
      return
    seq, status = data[2], data[3]
    job = self.inflight.pop(seq, None)
    if job is None:
      return
    self.oracle_response_count += 1
    self.oracle_failures = 0
    if job.generation != self.state_generation:
      return
    if status != 0:
      self._job_failure_locked(job)
      return

    cmac4 = data[4:8]
    mac28 = mac28_hex_from_cmac4(cmac4)
    if job.kind == "recover":
      self.recovery_remaining -= 1
      if mac28 == job.expected_mac28 and job.native_index is not None and job.candidate_message is not None:
        if not self._seed_tracker_from_recovery_locked(job.native_index, job.candidate_message):
          self.cooldown_until = self._monotonic() + ORACLE_FAILURE_COOLDOWN_S
      elif self.recovery_remaining <= 0:
        self.recovery_active = False
        self.cooldown_until = self._monotonic() + ORACLE_FAILURE_COOLDOWN_S
    elif job.kind == "verify":
      if mac28 == job.expected_mac28:
        self.qualified = True
        if self.tracker.event is not None and self.tracker.message_counter is not None:
          self._schedule_future_sign_locked(self.tracker.event, self.tracker.message_counter)
      elif self.tracker.event is not None:
        latest = self.tracker.event
        self.tracker = NativeFreshnessTracker()
        self._start_recovery_locked(latest)
    elif job.kind == "sign":
      key = job.target_key
      if key is not None:
        self.pending_targets.discard(key)
        if job.application is not None and job.reset_counter is not None and job.message_counter is not None:
          self.signed_cache[key] = build_signed_frame(
            job.application, job.reset_counter, job.message_counter, cmac4,
          )
          if self.tracker.event is not None and self.tracker.message_counter is not None:
            self._maybe_arm_locked(self.tracker.event, self.tracker.message_counter)

  def _job_failure_locked(self, job: OracleJob) -> None:
    key = job.target_key
    if key is not None:
      self.pending_targets.discard(key)
    if job.kind == "recover" and self.recovery_remaining > 0:
      self.recovery_remaining -= 1
    self.oracle_failures += 1
    if self.oracle_failures >= 4:
      self.oracle_timeout_count += self.oracle_failures
      self.oracle_failures = 0
      self.cooldown_until = self._monotonic() + ORACLE_FAILURE_COOLDOWN_S
      self._release_locked()
      self._clear_signed_state_locked()
      self.tracker = NativeFreshnessTracker()

  def _alloc_seq_locked(self) -> int:
    for _ in range(255):
      seq = self.next_oracle_seq
      self.next_oracle_seq = (seq % 255) + 1
      if seq not in self.inflight:
        return seq
    raise RuntimeError("oracle sequence space exhausted")

  def _expire_inflight_locked(self, now: float) -> None:
    expired = [seq for seq, job in self.inflight.items()
               if job.sent_at is not None and now - job.sent_at > ORACLE_TIMEOUT_S]
    for seq in expired:
      job = self.inflight.pop(seq)
      self._job_failure_locked(job)

  def _next_job_locked(self, now: float) -> tuple[int, OracleJob] | None:
    self._expire_inflight_locked(now)
    if now < self.cooldown_until or now < self.next_oracle_send_at or len(self.inflight) >= ORACLE_MAX_INFLIGHT:
      return None
    while self.jobs:
      job = self.jobs.popleft()
      if job.generation != self.state_generation:
        continue
      seq = self._alloc_seq_locked()
      job.sent_at = now
      self.inflight[seq] = job
      self.next_oracle_send_at = now + ORACLE_PERIOD_S
      return seq, job
    return None

  def _oracle_sender_loop(self) -> None:
    while True:
      with self._cv:
        if self._stop:
          return
        now = self._monotonic()
        item = self._next_job_locked(now)
        if item is None:
          self._cv.wait(timeout=0.005)
          continue
      seq, job = item
      ff, cfs = build_oracle_transport(seq, job.domain)
      self._send_can([ff])
      self._sleep(ORACLE_PRE_CF_DELAY_S)
      self._send_can(cfs)

  def update(self, can_list: list, CS: structs.CarState) -> None:
    with self._cv:
      self.stationary_park = self._stationary_park(CS)
      if not self.stationary_park and (self.active or self.arm_pending or self.qualified or self.recovery_active):
        self._fail_open_locked()

      for _, packets in can_list:
        for address, dat, src in packets:
          address_i, src_i, data = int(address), int(src), bytes(dat)
          if src_i >= PANDA_RETURNED_OFFSET:
            self._observe_tx_echo_locked(address_i, data, src_i)
            continue
          if src_i == UPSTREAM_BUS and address_i == SECOC_SYNC_ADDR:
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
