"""Exact-F33 authenticated 0x08A request-plane replacement.

The FRC remains the source of truth for the complete TSS3 request envelope. Once
freshness is qualified and Panda has atomically handed 0x08A forwarding to the
host, native ID11 keeps its source-real envelope with only the lateral pinion
angle replaced. Native ID0 is promoted to Toyota's observed ID11 shape by also
setting the request ID and B24 assist gain raw 100 (1.00). Other application IDs
remain source-real.

The host never learns the TSK key. It asks the EPS RAM resident to run ICU-S
command 5 / selector 4 over the ordinary 0x008A SecOC domain and receives only
CMAC[0:4]. Each modified frame is signed for the exact native generation that
was observed; the host does not predict future 0x08A application contents.
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
from opendbc.car.toyota.tss3 import target_angle_deg_to_raw
from opendbc.car.toyota.values import CAR, ToyotaSafetyFlags
from openpilot.common.swaglog import cloudlog
from openpilot.selfdrive.car.toyota_tss3_08a import (
  ADMIN_ADDR,
  ADMIN_BUS,
  DOWNSTREAM_BUS,
  NATIVE_08A_ADDR,
  PANDA_REJECTED_OFFSET,
  PANDA_RETURNED_OFFSET,
  SECOC_SYNC_ADDR,
  STABLE_NATIVE_FRAMES,
  SYNC_BUS,
  UPSTREAM_BUS,
  SendCan,
  decode_sync,
  make_admin,
)

ORACLE_REQUEST_ADDR = 0x7A1
ORACLE_RESPONSE_ADDR = 0x7A9
ORACLE_BUS = 0
ORACLE_PRIVATE_SID = 0xC9
ORACLE_DOMAIN_LEN = 36
ORACLE_NSDU_LEN = 40
ORACLE_PRE_CF_DELAY_S = 0.005
ORACLE_PERIOD_S = 0.025
ORACLE_TIMEOUT_S = 0.12
ORACLE_SIGN_TIMEOUT_S = 0.045
ORACLE_SIGN_REPAIR_TIMEOUT_S = 0.025
ORACLE_VERIFY_MAX_RETRIES = 2
ORACLE_MAX_INFLIGHT = 4
ORACLE_FAILURE_COOLDOWN_S = 2.0
AUTHORITY_FAILURE_ALERT_S = 1.0
MAX_NATIVE_HISTORY = 256
MAX_NATIVE_GAP = 8

TSS3_IDLE_ID = 0
TSS3_LDA_ID = 4
TSS3_LTA_LCA_ID = 11
TSS3_SDG_ID = 18
# Exact Camry road corpus: these are the only observed lateral request owners.
# While comma owns the request plane, every one of them is replaced by ID11;
# none is allowed to pass through as a competing Toyota lateral owner.
TSS3_LATERAL_SOURCE_IDS = (TSS3_IDLE_ID, TSS3_LDA_ID, TSS3_LTA_LCA_ID, TSS3_SDG_ID)
TSS3_LTA_ASSIST_GAIN_RAW = 100
LATERAL_ANGLE_OFFSET = 18
LATERAL_ANGLE_SIZE = 2

JobKind = Literal["recover", "verify", "sign"]


def request_plane_enabled(CP: structs.CarParams) -> bool:
  """Return whether CarParams selected the relay-correct F33 request plane."""
  return (CP.carFingerprint == CAR.TOYOTA_CAMRY_TSS3 and not CP.passive and bool(CP.safetyConfigs) and
          bool(CP.safetyConfigs[0].safetyParam & ToyotaSafetyFlags.TSS3_08A_HOST.value) and
          bool(CP.safetyConfigs[0].safetyParam & ToyotaSafetyFlags.TSS3_08A_SIGNED.value))


def shift_reset_epoch(trip_counter: int, reset_counter: int, delta: int) -> tuple[int, int]:
  packed = (((trip_counter << 20) | reset_counter) + delta) & ((1 << 36) - 1)
  return packed >> 20, packed & ((1 << 20) - 1)


def resolve_epoch(sync_trip: int, sync_reset: int, reset_low2: int) -> tuple[int, int] | None:
  """Resolve native FV4 against nearby 0x00F state without assuming publication order.

  0x00F and 0x08A are asynchronous. Around a normal reset transition either
  carrier can be one publication ahead, so the native frame's reset-low2 is the
  per-generation authority and 0x00F supplies only the nearby full-counter epoch.
  """
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


def build_id11_application(native_application: bytes, target_angle_raw: int) -> bytes:
  """Build comma's ID11 request from any observed Toyota lateral owner.

  The FRC can select ID0 (no request), ID4 (LDA), ID11 (LTA/LCA), or ID18
  (SDG/PDA-SA) on this Camry. Once comma owns the request plane, allowing any of
  those Toyota identities through would break the chain of authority. Preserve
  the exact source generation/envelope, but force the lateral owner to ID11,
  replace the pinion target, and normalize B24 to the observed ID11 assist gain
  raw 100. The exact modified generation is re-signed by the EPS oracle.
  """
  if len(native_application) != 28:
    raise ValueError("native 0x08A application must be 28 bytes")
  native_id = native_application[21] & 0x3F
  if native_id not in TSS3_LATERAL_SOURCE_IDS:
    raise ValueError(f"unsupported native lateral request ID {native_id}")
  if not -(1 << 15) <= target_angle_raw < (1 << 15):
    raise ValueError("target angle must fit signed16")
  application = bytearray(native_application)
  application[21] = (application[21] & 0xC0) | TSS3_LTA_LCA_ID
  application[LATERAL_ANGLE_OFFSET:LATERAL_ANGLE_OFFSET + LATERAL_ANGLE_SIZE] = target_angle_raw.to_bytes(2, "big", signed=True)
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
  mac28_hex: str

  @property
  def target_id(self) -> int:
    return self.application[21] & 0x3F


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
    """Return (valid, reset_counter_changed).

    Toyota's 8-bit SecOC message counter is local to each reset-counter epoch:
    the first 0x08A generation of every newly resolved reset epoch is message 1,
    then it increments with the native B26 generation sequence inside that epoch.
    The full Camry route validates this across 874 reset transitions and 19
    independent oracle-proven full-counter anchors.
    """
    if self.event is None or self.message_counter is None:
      return False, False
    prev = self.event
    reset_changed = (event.trip_counter, event.reset_counter) != (prev.trip_counter, prev.reset_counter)
    delta = (event.b26 - prev.b26) & 0x3F
    if not 1 <= delta <= MAX_NATIVE_GAP:
      return False, False

    if reset_changed:
      # A source-real reset epoch starts at message counter 1. If the first
      # observed frame is not low2=1, we missed the boundary; force recovery
      # rather than guessing the high counter bits.
      if event.message_low2 != 1:
        return False, True
      message = 1
    else:
      message = (self.message_counter + delta) & 0xFF
      if (message & 0x3) != event.message_low2:
        return False, False

    self.event = event
    self.message_counter = message
    return True, reset_changed


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
  sent_at: float | None = None
  retry_count: int = 0
  flow_control_seen: bool = False
  cf_repair_sent_at: float | None = None


@dataclass
class PendingOutput:
  native_frame: bytes
  ready_frame: bytes | None
  modified: bool


class ToyotaTss3RequestProxy:
  """Source-ordered exact-F33 0x08A proxy with selective ID11 angle substitution."""

  def __init__(self, send_can: SendCan, *, start_thread: bool = True,
               monotonic=time.monotonic, sleep=time.sleep):
    self._send_can = send_can
    self._monotonic = monotonic
    self._sleep = sleep
    self._lock = threading.RLock()
    self._cv = threading.Condition(self._lock)
    self._stop = False
    self._thread: threading.Thread | None = None

    self.can_valid = False
    self.control_lat_active = False
    self.control_target_angle_raw = 0
    self.native_cruise_operating = False
    self.brake_pressed = False

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

    self.active = False
    self.arm_pending = False
    self.arm_admin_data: bytes | None = None
    self.arm_accepted = False
    self.arm_clone_index: int | None = None
    self.arm_clone_frame: bytes | None = None

    self.pending_outputs: dict[int, PendingOutput] = {}
    self.next_output_index: int | None = None

    self.arm_count = 0
    self.modified_tx_count = 0
    self.transparent_tx_count = 0
    self.release_count = 0
    self.oracle_response_count = 0
    self.oracle_timeout_count = 0
    self.recovery_count = 0
    self.verification_count = 0
    self.authority_failure_count = 0
    self.last_authority_failure_reason = ""
    self.authority_failure_alert_until = 0.0

    if start_thread:
      self._thread = threading.Thread(target=self._oracle_sender_loop, name="tss3_08a_oracle", daemon=True)
      self._thread.start()

  def set_control(self, lat_active: bool, target_angle_deg: float) -> None:
    with self._cv:
      was_lat_active = self.control_lat_active
      self.control_lat_active = bool(lat_active)
      self.control_target_angle_raw = target_angle_deg_to_raw(float(target_angle_deg))

      # Relay ownership follows the normal openpilot lateral-authority boundary.
      # Do not proxy exact Toyota frames through driver override/disengagement:
      # CarController resets its angle target to measured steering while
      # CC.latActive is false, and Panda must begin the next handoff from that
      # same baseline.
      if was_lat_active and not self.control_lat_active:
        self._release_control_locked()
      elif not was_lat_active and self.control_lat_active:
        self._maybe_arm_locked()

  def authority_failure_alert_active(self) -> bool:
    with self._cv:
      # A transient failure gets a short warning pulse. More importantly, never
      # let openpilot claim lateral activity silently while the request plane has
      # neither active authority nor an atomic handoff in progress.
      unavailable = self.control_lat_active and not (self.active or self.arm_pending)
      return self._monotonic() < self.authority_failure_alert_until or unavailable

  def _record_failure_locked(self, reason: str, *, full_recovery: bool) -> None:
    self.authority_failure_count += 1
    self.last_authority_failure_reason = reason
    now = self._monotonic()
    self.authority_failure_alert_until = max(self.authority_failure_alert_until, now + AUTHORITY_FAILURE_ALERT_S)
    cloudlog.event(
      "toyota_f33_request_plane_failure",
      reason=reason,
      count=self.authority_failure_count,
      full_recovery=full_recovery,
      active=self.active,
      arm_pending=self.arm_pending,
      qualified=self.qualified,
      native_index=self.native_index,
      pending_outputs=len(self.pending_outputs),
      inflight=len(self.inflight),
      error=True,
    )

  def _authority_failure_locked(self, reason: str) -> None:
    # Panda/transport authority failure is not a SecOC freshness failure. Drop
    # only the current authority interval and preserve the proven tracker and
    # qualification so the next eligible native generation can re-arm.
    self._record_failure_locked(reason, full_recovery=False)
    self._release_control_locked(restore_pending=False)

  def _release_control_locked(self, *, restore_pending: bool = False) -> None:
    self._release_locked(restore_pending=restore_pending)
    # Sign work belongs to the authority interval that just ended. Preserve the
    # recovered native freshness tracker/qualification, but invalidate queued
    # and in-flight modified generations so they cannot transmit after release.
    self.state_generation += 1
    self.jobs.clear()
    self.inflight.clear()
    self._cv.notify_all()

  def _clear_oracle_state_locked(self) -> None:
    self.state_generation += 1
    self.jobs.clear()
    self.inflight.clear()
    self.qualified = False
    self.recovery_active = False
    self.recovery_sample_index = None
    self.recovery_remaining = 0
    self._cv.notify_all()

  def _flush_outputs_locked(self) -> None:
    if self.next_output_index is None:
      return
    out: list[CanData] = []
    while True:
      slot = self.pending_outputs.get(self.next_output_index)
      if slot is None or slot.ready_frame is None:
        break
      out.append(CanData(NATIVE_08A_ADDR, slot.ready_frame, DOWNSTREAM_BUS))
      if slot.modified:
        self.modified_tx_count += 1
      else:
        self.transparent_tx_count += 1
      del self.pending_outputs[self.next_output_index]
      self.next_output_index += 1
    if out:
      self._send_can(out)

  def _restore_pending_native_locked(self) -> None:
    for slot in self.pending_outputs.values():
      slot.ready_frame = slot.native_frame
      slot.modified = False
    self._flush_outputs_locked()

  def _release_locked(self, *, restore_pending: bool = False, send_admin: bool = True) -> None:
    was_active = self.active
    was_arm_pending = self.arm_pending

    # End logical authority atomically. Pending blocked source generations are
    # discarded rather than replayed as Toyota requests at the comma->stock
    # ownership boundary; stock forwarding resumes with the next native frame.
    self.active = False
    self.arm_pending = False

    if restore_pending and was_active:
      self._restore_pending_native_locked()
    if send_admin and (was_active or was_arm_pending):
      self._send_can([make_admin(False)])
      self.release_count += 1
    self.arm_admin_data = None
    self.arm_accepted = False
    self.arm_clone_index = None
    self.arm_clone_frame = None
    self.pending_outputs.clear()
    self.next_output_index = None

  def _fail_open_locked(self, reason: str) -> None:
    # Initial startup can see native 0x08A before the first usable 0x00F sync;
    # that is not an authority failure and should not warn the driver. Once any
    # freshness/authority state exists, a full reset is a real visible failure.
    had_state = self.active or self.arm_pending or self.qualified or self.recovery_active or self.tracker.event is not None
    if had_state:
      self._record_failure_locked(reason, full_recovery=True)
    self._release_locked()
    self._clear_oracle_state_locked()
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
    self._clear_oracle_state_locked()
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
    self.state_generation += 1
    self.jobs.clear()
    self.inflight.clear()
    self.recovery_active = False
    self.recovery_sample_index = None
    self.recovery_remaining = 0
    self.qualified = False
    if tracker.event is not None and tracker.message_counter is not None:
      self._queue_verify_locked(tracker.event, tracker.message_counter)
    return True

  def _queue_verify_locked(self, event: NativeEvent, message_counter: int, *, retry_count: int = 0) -> None:
    self.verification_count += 1
    self._queue_job_locked(OracleJob(
      kind="verify",
      generation=self.state_generation,
      domain=build_secoc_domain(event.application, event.trip_counter, event.reset_counter, message_counter),
      expected_mac28=event.mac28_hex,
      native_index=event.index,
      candidate_message=message_counter,
      retry_count=retry_count,
    ), front=True)

  def _maybe_arm_locked(self) -> None:
    if (self.active or self.arm_pending or not self.control_lat_active or not self.native_cruise_operating or
        self.brake_pressed or not self.qualified or not self.can_valid):
      return
    admin = make_admin(True)
    self._send_can([admin])
    self.arm_pending = True
    self.arm_admin_data = admin.dat
    self.arm_accepted = False

  def _make_native_event_locked(self, frame: bytes) -> NativeEvent | None:
    if len(frame) != 32 or self.sync_trip is None or self.sync_reset is None:
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
    self.sync_trip, self.sync_reset = trip, reset

  def _queue_active_output_locked(self, event: NativeEvent, message_counter: int) -> None:
    if self.next_output_index is None:
      self.next_output_index = event.index

    native = event.frame
    if not self.control_lat_active:
      self.pending_outputs[event.index] = PendingOutput(native, native, False)
      self._flush_outputs_locked()
      return
    if event.target_id not in TSS3_LATERAL_SOURCE_IDS:
      # Unknown Toyota lateral semantics are not a valid fallback while comma
      # claims request-plane authority. End this authority interval instead of
      # submitting a competing Toyota owner to Brake/VMM.
      self._authority_failure_locked("unsupported_native_lateral_id")
      return

    application = build_id11_application(event.application, self.control_target_angle_raw)
    if application == event.application:
      self.pending_outputs[event.index] = PendingOutput(native, native, False)
      self._flush_outputs_locked()
      return

    self.pending_outputs[event.index] = PendingOutput(native, None, True)
    self._queue_job_locked(OracleJob(
      kind="sign",
      generation=self.state_generation,
      domain=build_secoc_domain(application, event.trip_counter, event.reset_counter, message_counter),
      native_index=event.index,
      application=application,
      trip_counter=event.trip_counter,
      reset_counter=event.reset_counter,
      message_counter=message_counter,
    ))

  def _observe_native_locked(self, frame: bytes) -> None:
    event = self._make_native_event_locked(frame)
    if event is None or not self.can_valid:
      self._fail_open_locked("native_event_invalid")
      return

    # Use the same source-real cruise latch that Panda uses for controls_allowed.
    # This closes the one-generation race where controlsd can still report
    # latActive after Toyota has already dropped steering authority.
    self.native_cruise_operating = bool(frame[3] & 0x08)

    if self.last_native_b26 is not None and event.b26 == ((self.last_native_b26 + 1) & 0x3F):
      self.stable_native_frames += 1
    else:
      self.stable_native_frames = 1
    self.last_native_b26 = event.b26
    self.history.append(event)

    if not self.native_cruise_operating and (self.active or self.arm_pending):
      # Toyota withdrew the source-side operating latch. This ends the comma
      # authority interval; do not replay the blocked withdrawal generation as
      # Toyota while the host still owns the relay. Release first and let the
      # next native publication cross under stock forwarding.
      self._release_control_locked()
      return

    if self.tracker.event is None or self.tracker.message_counter is None:
      if self.stable_native_frames >= STABLE_NATIVE_FRAMES:
        self._start_recovery_locked(event)
      return

    valid, _ = self.tracker.update(event)
    if not valid or self.tracker.message_counter is None:
      # A recorder/comma scheduling gap can deliver several seconds of native
      # 0x08A backlog before the matching 0x00F sync frames in the same batch.
      # Do not recover from that first stale-epoch frame. Drop qualification and
      # let the ordinary STABLE_NATIVE_FRAMES path restart recovery only after
      # native cadence has become consecutive again; by then 0x00F has caught up.
      self.tracker = NativeFreshnessTracker()
      self._fail_open_locked("freshness_lost")
      return

    message_counter = self.tracker.message_counter

    if self.arm_pending:
      self.arm_clone_index = event.index
      self.arm_clone_frame = event.frame
      self._send_can([CanData(NATIVE_08A_ADDR, event.frame, DOWNSTREAM_BUS)])
    elif self.active:
      self._queue_active_output_locked(event, message_counter)

    self._maybe_arm_locked()

  def _observe_tx_echo_locked(self, address: int, data: bytes, src: int) -> None:
    if address == ADMIN_ADDR and self.arm_pending and data == self.arm_admin_data:
      if src == ADMIN_BUS + PANDA_RETURNED_OFFSET:
        self.arm_accepted = True
      elif src == ADMIN_BUS + PANDA_REJECTED_OFFSET:
        self._authority_failure_locked("arm_admin_rejected")
      return

    if address != NATIVE_08A_ADDR:
      return

    if src == DOWNSTREAM_BUS + PANDA_RETURNED_OFFSET and self.arm_pending and self.arm_accepted and data == self.arm_clone_frame:
      self.active = True
      self.arm_pending = False
      self.arm_admin_data = None
      self.arm_accepted = False
      self.next_output_index = (self.arm_clone_index + 1) if self.arm_clone_index is not None else None
      self.arm_clone_index = None
      self.arm_clone_frame = None
      self.arm_count += 1
    elif src == DOWNSTREAM_BUS + PANDA_REJECTED_OFFSET and self.arm_pending and data == self.arm_clone_frame:
      self._authority_failure_locked("handoff_clone_rejected")
    elif src == DOWNSTREAM_BUS + PANDA_REJECTED_OFFSET and self.active:
      self._authority_failure_locked("host_08a_rejected")

  def _observe_oracle_response_locked(self, data: bytes) -> None:
    if len(data) != 8:
      return
    if data[:3] == bytes((0x30, 0x00, ORACLE_NSDU_LEN)):
      # Active signing uses one transaction at a time. The production fast path
      # sends CF1..CF5 speculatively after 5 ms; when the EPS later emits its real
      # ISO-TP flow-control without a private reply in the same incoming CAN
      # batch, wake the sender to repeat only those CFs for this same FF/session.
      sign_jobs = [(seq, job) for seq, job in self.inflight.items() if job.kind == "sign"]
      if len(sign_jobs) == 1:
        _, job = sign_jobs[0]
        job.flow_control_seen = True
        self._cv.notify_all()
      return
    if data[0] != 0x07 or data[1] != ORACLE_PRIVATE_SID:
      return
    seq, status = data[2], data[3]
    job = self.inflight.pop(seq, None)
    if job is None:
      return
    self.oracle_response_count += 1
    self._cv.notify_all()
    if job.generation != self.state_generation:
      return
    if status != 0:
      self._job_failure_locked(job)
      return

    cmac4 = data[4:8]
    mac28 = mac28_hex_from_cmac4(cmac4)
    self.oracle_failures = 0
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
        self._maybe_arm_locked()
      elif self.tracker.event is not None:
        latest = self.tracker.event
        self.tracker = NativeFreshnessTracker()
        self._start_recovery_locked(latest)
    elif job.kind == "sign":
      if None in (job.native_index, job.application, job.reset_counter, job.message_counter):
        self._authority_failure_locked("invalid_sign_job")
        return
      slot = self.pending_outputs.get(int(job.native_index))
      if slot is None:
        return
      slot.ready_frame = build_signed_frame(job.application, int(job.reset_counter), int(job.message_counter), cmac4)
      self._flush_outputs_locked()

  def _job_failure_locked(self, job: OracleJob) -> None:
    if job.kind == "sign":
      self.oracle_timeout_count += 1
      self._authority_failure_locked("oracle_sign_failure")
      return

    if job.kind == "verify":
      # Verification is the final qualification step. A single missing private
      # C9 response must never strand the proxy forever with a valid tracker but
      # qualified=False. Retry against the *current* tracker event because native
      # freshness may have advanced while the prior verify was in flight.
      if (job.retry_count < ORACLE_VERIFY_MAX_RETRIES and self.tracker.event is not None and
          self.tracker.message_counter is not None):
        self._queue_verify_locked(self.tracker.event, self.tracker.message_counter, retry_count=job.retry_count + 1)
        return

      self.oracle_timeout_count += 1
      self._fail_open_locked("oracle_verify_failure")
      return

    if job.kind == "recover" and self.recovery_remaining > 0:
      self.recovery_remaining -= 1
    self.oracle_failures += 1
    if self.oracle_failures >= 4:
      self.oracle_timeout_count += self.oracle_failures
      self.oracle_failures = 0
      self.cooldown_until = self._monotonic() + ORACLE_FAILURE_COOLDOWN_S
      self._fail_open_locked("oracle_recovery_failure")

  def _alloc_seq_locked(self) -> int:
    for _ in range(255):
      seq = self.next_oracle_seq
      self.next_oracle_seq = (seq % 255) + 1
      if seq not in self.inflight:
        return seq
    raise RuntimeError("oracle sequence space exhausted")

  def _expire_inflight_locked(self, now: float) -> None:
    expired = []
    for seq, job in self.inflight.items():
      if job.kind == "sign":
        if job.sent_at is None:
          continue
        deadline = job.sent_at + ORACLE_SIGN_TIMEOUT_S
        if job.cf_repair_sent_at is not None:
          deadline = max(deadline, job.cf_repair_sent_at + ORACLE_SIGN_REPAIR_TIMEOUT_S)
        if now > deadline:
          expired.append(seq)
      elif job.sent_at is not None and now - job.sent_at > ORACLE_TIMEOUT_S:
        expired.append(seq)

    for seq in expired:
      job = self.inflight.pop(seq)
      # A sign failure after same-session CF repair ends this authority interval.
      # Never skip the source generation, replay Toyota under comma authority, or
      # start a fresh FF whose latency would build a multi-generation backlog.
      self._job_failure_locked(job)

  def _next_cf_repair_locked(self, now: float) -> tuple[int, OracleJob] | None:
    for seq, job in self.inflight.items():
      if (job.kind == "sign" and job.generation == self.state_generation and
          job.flow_control_seen and job.cf_repair_sent_at is None):
        job.cf_repair_sent_at = now
        return seq, job
    return None

  def _next_job_locked(self, now: float) -> tuple[int, OracleJob] | None:
    self._expire_inflight_locked(now)
    if now < self.cooldown_until:
      return None

    while self.jobs and self.jobs[0].generation != self.state_generation:
      self.jobs.popleft()
    if not self.jobs:
      return None

    job = self.jobs[0]
    if job.kind == "sign":
      # Active command-5 signing is strictly serialized. Real-road failures
      # showed that overlapping sign transactions can each receive ISO-TP FC
      # while one private 0xC9 response disappears. One-at-a-time service keeps
      # source order explicit; successful responses wake this sender immediately,
      # so the observed 22.3-ms mean RTT provides catch-up capacity vs 25-ms 0x08A.
      if self.inflight:
        return None
      self.jobs.popleft()
      seq = self._alloc_seq_locked()
      job.sent_at = now
      self.inflight[seq] = job
      return seq, job

    if now < self.next_oracle_send_at or len(self.inflight) >= ORACLE_MAX_INFLIGHT:
      return None

    self.jobs.popleft()
    seq = self._alloc_seq_locked()
    job.sent_at = now
    self.inflight[seq] = job
    # Recovery/verify retain the qualified 40-Hz pipelined transport and
    # phase-lock to the prior deadline so scheduler lateness does not accumulate.
    if self.next_oracle_send_at <= 0.0:
      self.next_oracle_send_at = now + ORACLE_PERIOD_S
    else:
      next_deadline = self.next_oracle_send_at + ORACLE_PERIOD_S
      self.next_oracle_send_at = next_deadline if next_deadline > now else now + ORACLE_PERIOD_S
    return seq, job

  def _oracle_sender_loop(self) -> None:
    while True:
      with self._cv:
        if self._stop:
          return
        now = self._monotonic()
        repair = self._next_cf_repair_locked(now)
        if repair is not None:
          seq, job = repair
          _, cfs = build_oracle_transport(seq, job.domain)
          # Same FF/session, same transaction sequence: repair only receiver
          # admission. No new signing request or source generation is created.
          self._send_can(cfs)
          continue
        item = self._next_job_locked(now)
        if item is None:
          self._cv.wait(timeout=0.005)
          continue
      seq, job = item
      ff, cfs = build_oracle_transport(seq, job.domain)
      self._send_can([ff])
      self._sleep(ORACLE_PRE_CF_DELAY_S)
      # Fast first attempt; a later EPS FC can trigger one same-session CF repair.
      self._send_can(cfs)

  def update(self, can_list: list, CS: structs.CarState) -> None:
    with self._cv:
      self.can_valid = bool(CS.canValid)
      self.brake_pressed = bool(getattr(CS, "brakePressed", False))
      if not self.can_valid and (self.active or self.arm_pending or self.qualified or self.recovery_active):
        self._fail_open_locked("can_invalid")
      elif self.brake_pressed and (self.active or self.arm_pending):
        # Panda's generic safety logic revokes controls_allowed immediately on
        # brake press, which can precede controlsd's latActive=False by a few ms.
        # Release on the same fresh CarState boundary to avoid one stale ID11.
        self._release_control_locked()

      for _, packets in can_list:
        for address, dat, src in packets:
          address_i, src_i, data = int(address), int(src), bytes(dat)
          if src_i >= PANDA_RETURNED_OFFSET:
            self._observe_tx_echo_locked(address_i, data, src_i)
            continue
          if src_i == SYNC_BUS and address_i == SECOC_SYNC_ADDR:
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


# Compatibility name for the development Param and older analysis imports.
ToyotaTss3SignedId0Proxy = ToyotaTss3RequestProxy
