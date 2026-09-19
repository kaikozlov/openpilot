from types import SimpleNamespace

from opendbc.car.can_definitions import CanData
from opendbc.car.toyota.tss3 import TSS3_B6_TARGET_ANGLE_SCALE_DEG
from opendbc.car.toyota.values import CAR, ToyotaSafetyFlags
from openpilot.selfdrive.car.toyota_tss3_08a import ADMIN_ADDR, ADMIN_BUS, DOWNSTREAM_BUS, NATIVE_08A_ADDR, PANDA_REJECTED_OFFSET, SECOC_SYNC_ADDR
from openpilot.selfdrive.car.toyota_tss3_08a_signed import (
  ORACLE_BUS,
  ORACLE_RESPONSE_ADDR,
  OracleJob,
  PendingOutput,
  NativeEvent,
  NativeFreshnessTracker,
  ToyotaTss3RequestProxy,
  build_id11_application,
  build_oracle_transport,
  build_secoc_domain,
  build_signed_frame,
  request_plane_enabled,
  resolve_epoch,
)

KNOWN_DOMAIN = bytes.fromhex(
  "008a0000000080000012ffae00ffae7fff007fff004b0000000000001e00026c00455084"
)
KNOWN_APP = KNOWN_DOMAIN[2:30]
KNOWN_CMAC4 = bytes.fromhex("d64e2a5e")
KNOWN_MAC28 = "d64e2a5"


def sync_frame(trip: int = 620, reset: int = 1109) -> bytes:
  data = bytearray(8)
  data[0:2] = trip.to_bytes(2, "big")
  data[2] = (reset >> 12) & 0xFF
  data[3] = (reset >> 4) & 0xFF
  data[4] = (reset & 0xF) << 4
  return bytes(data)


def native_frame(b26: int, message: int, *, trip: int = 620, reset: int = 1109,
                 target_id: int = 0, angle_raw: int = 0, semantic: int = 0x40,
                 mac28: str = KNOWN_MAC28, cruise: bool = True) -> bytes:
  app = bytearray(KNOWN_APP)
  if cruise:
    app[3] |= 0x08
  else:
    app[3] &= ~0x08
  app[18:20] = angle_raw.to_bytes(2, "big", signed=True)
  app[21] = (app[21] & 0xC0) | (target_id & 0x3F)
  app[22] = semantic
  app[26] = (app[26] & 0xC0) | (b26 & 0x3F)
  fv4 = ((message & 0x3) << 2) | (reset & 0x3)
  trailer = bytes.fromhex(f"{fv4:x}{mac28}")
  return bytes(app) + trailer


def event(index: int, b26: int, message: int, *, trip: int = 620, reset: int = 1109,
          target_id: int = 0, angle_raw: int = 0) -> NativeEvent:
  frame = native_frame(b26, message, trip=trip, reset=reset, target_id=target_id, angle_raw=angle_raw)
  return NativeEvent(index, frame, frame[:28], b26, trip, reset, message & 3, KNOWN_MAC28)


def batch(*frames: tuple[int, bytes, int]):
  return [(1_000_000_000, list(frames))]


def cs(*, valid: bool = True, brake: bool = False, steering_angle_deg: float = 0.0):
  return SimpleNamespace(
    canValid=valid,
    brakePressed=brake,
    steeringAngleDeg=steering_angle_deg,
    steeringAngleOffsetDeg=0.0,
  )


class Collector:
  def __init__(self):
    self.batches: list[list[CanData]] = []

  def __call__(self, msgs: list[CanData]):
    self.batches.append(list(msgs))

  @property
  def flat(self):
    return [m for b in self.batches for m in b]


def response(seq: int, cmac4: bytes, status: int = 0) -> tuple[int, bytes, int]:
  return ORACLE_RESPONSE_ADDR, bytes((0x07, 0xC9, seq, status)) + cmac4, ORACLE_BUS


def put_inflight(worker: ToyotaTss3RequestProxy, seq: int, job):
  worker.inflight[seq] = job


def qualify(worker: ToyotaTss3RequestProxy, collector: Collector, *, next_seq: int = 1) -> int:
  state = cs()
  worker.set_control(True, 0.0)
  worker.update(batch((SECOC_SYNC_ADDR, sync_frame(), 0)), state)
  for i in range(8):
    worker.update(batch((NATIVE_08A_ADDR, native_frame(i, i + 1, semantic=0x50 + i), 2)), state)
  assert worker.recovery_active

  # The eighth source frame has message8=8 / low2=0. Resolve the full counter
  # through native MAC equality, then verify the reconstructed current event.
  for expected_message in (0, 4, 8):
    job = worker.jobs.popleft()
    assert job.candidate_message == expected_message
    put_inflight(worker, next_seq, job)
    cmac = KNOWN_CMAC4 if expected_message == 8 else bytes.fromhex("aaaaaaaa")
    worker.update(batch(response(next_seq, cmac)), state)
    next_seq += 1

  verify = worker.jobs.popleft()
  assert verify.kind == "verify" and verify.candidate_message == 8
  put_inflight(worker, next_seq, verify)
  worker.update(batch(response(next_seq, KNOWN_CMAC4)), state)
  next_seq += 1
  assert worker.qualified and worker.arm_pending
  admin = collector.flat[-1]
  assert admin == CanData(ADMIN_ADDR, bytes.fromhex("07c9a80100000000"), ADMIN_BUS)
  worker.update(batch((ADMIN_ADDR, admin.dat, ADMIN_BUS + 0x80)), state)
  assert worker.arm_accepted

  # Handoff itself is an exact source clone. Panda's returned TX echo is the
  # ownership acknowledgement; no future-generation prediction is involved.
  handoff = native_frame(8, 9, semantic=0x58)
  worker.update(batch((NATIVE_08A_ADDR, handoff, 2)), state)
  assert collector.flat[-1] == CanData(NATIVE_08A_ADDR, handoff, 0)
  worker.update(batch((NATIVE_08A_ADDR, handoff, 0x80)), state)
  assert worker.active and not worker.arm_pending
  return next_seq


def test_known_live_domain_and_trailer_geometry():
  assert build_secoc_domain(KNOWN_APP, 620, 1109, 8) == KNOWN_DOMAIN
  assert build_signed_frame(KNOWN_APP, 1109, 8, KNOWN_CMAC4).hex() == KNOWN_APP.hex() + "1d64e2a5"


def test_known_live_oracle_transport_geometry():
  ff, cfs = build_oracle_transport(1, KNOWN_DOMAIN)
  assert ff == CanData(0x7A1, bytes.fromhex("1028c9c901008a00"), ORACLE_BUS)
  assert [m.dat.hex() for m in cfs] == [
    "2100000080000012",
    "22ffae00ffae7fff",
    "23007fff004b0000",
    "24000000001e0002",
    "256c00455084fe00",
  ]


def test_resolve_epoch_nearest_low2():
  assert resolve_epoch(620, 1109, 1109 & 3) == (620, 1109)
  assert resolve_epoch(620, 1109, 1108 & 3) == (620, 1108)
  assert resolve_epoch(620, 1109, 1110 & 3) == (620, 1110)


def test_freshness_tracker_resets_message_counter_on_new_reset_epoch():
  tracker = NativeFreshnessTracker()
  assert tracker.seed(event(1, 10, 8), 8)
  ok, reset_changed = tracker.update(event(2, 11, 9))
  assert ok and not reset_changed and tracker.message_counter == 9
  ok, reset_changed = tracker.update(event(3, 13, 11))
  assert ok and not reset_changed and tracker.message_counter == 11

  # Source-real Camry behavior: the first 0x08A in a new reset epoch uses
  # full message counter 1, independent of the previous epoch's full counter.
  ok, reset_changed = tracker.update(event(4, 14, 1, reset=1110))
  assert ok and reset_changed and tracker.message_counter == 1
  ok, reset_changed = tracker.update(event(5, 15, 2, reset=1110))
  assert ok and not reset_changed and tracker.message_counter == 2


def test_freshness_tracker_rejects_missed_reset_boundary():
  tracker = NativeFreshnessTracker()
  assert tracker.seed(event(1, 10, 8), 8)
  # If the first observed generation in the new epoch is not low2=1, the
  # boundary was missed and full-counter recovery is required.
  ok, reset_changed = tracker.update(event(2, 13, 3, reset=1110))
  assert not ok and reset_changed


def test_id11_builder_preserves_native_envelope_and_promotes_id0():
  native11 = native_frame(4, 5, target_id=11, angle_raw=123, semantic=0x77)[:28]
  modified11 = build_id11_application(native11, -456)
  assert modified11[18:20] == (-456).to_bytes(2, "big", signed=True)
  assert modified11[:18] == native11[:18]
  assert modified11[20:] == native11[20:]

  native0 = native_frame(4, 5, target_id=0, angle_raw=123, semantic=0x78)[:28]
  modified0 = build_id11_application(native0, 321)
  assert modified0[18:20] == (321).to_bytes(2, "big", signed=True)
  assert modified0[21] == ((native0[21] & 0xC0) | 11)
  assert modified0[24] == 100
  for i in range(28):
    if i not in (18, 19, 21, 24):
      assert modified0[i] == native0[i]

  id18 = native_frame(4, 5, target_id=18)[:28]
  try:
    build_id11_application(id18, 0)
  except ValueError:
    pass
  else:
    raise AssertionError("non-ID0/ID11 application unexpectedly accepted")


def test_relay_ownership_follows_lat_active_without_losing_qualification():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  qualify(worker, collector)
  assert worker.active and worker.qualified

  worker.set_control(False, 0.0)
  assert not worker.active and worker.qualified
  assert collector.flat[-1] == CanData(ADMIN_ADDR, bytes.fromhex("07c9a80000000000"), ADMIN_BUS)

  # Re-enable uses the already-qualified freshness state and begins a new
  # atomic handoff without running recovery again.
  recovery_before = worker.recovery_count
  worker.set_control(True, 0.5)
  assert worker.arm_pending and worker.qualified
  assert worker.recovery_count == recovery_before
  assert collector.flat[-1] == CanData(ADMIN_ADDR, bytes.fromhex("07c9a80100000000"), ADMIN_BUS)


def test_inactive_qualified_proxy_does_not_arm_until_lat_active():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  # Qualify manually while lateral is inactive.
  state = cs()
  worker.update(batch((SECOC_SYNC_ADDR, sync_frame(), 0)), state)
  for i in range(8):
    worker.update(batch((NATIVE_08A_ADDR, native_frame(i, i + 1, semantic=0x50 + i), 2)), state)
  seq = 1
  for expected_message in (0, 4, 8):
    job = worker.jobs.popleft()
    put_inflight(worker, seq, job)
    worker.update(batch(response(seq, KNOWN_CMAC4 if expected_message == 8 else bytes.fromhex("aaaaaaaa"))), state)
    seq += 1
  verify = worker.jobs.popleft()
  put_inflight(worker, seq, verify)
  worker.update(batch(response(seq, KNOWN_CMAC4)), state)
  assert worker.qualified and not worker.active and not worker.arm_pending

  worker.set_control(True, 0.0)
  assert worker.arm_pending


def test_verify_timeout_retries_current_tracker_and_can_qualify():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  state = cs()
  worker.update(batch((SECOC_SYNC_ADDR, sync_frame(), 0)), state)
  source = native_frame(7, 8, semantic=0x57)
  event_now = worker._make_native_event_locked(source)
  assert event_now is not None
  assert worker.tracker.seed(event_now, 8)
  worker.state_generation = 7

  verify = OracleJob(
    kind="verify", generation=7,
    domain=build_secoc_domain(event_now.application, event_now.trip_counter, event_now.reset_counter, 8),
    expected_mac28=event_now.mac28_hex, native_index=event_now.index, candidate_message=8,
    sent_at=1.0,
  )
  worker.inflight[10] = verify
  with worker._cv:
    worker._expire_inflight_locked(1.121)

  assert not worker.qualified
  assert not worker.inflight
  assert worker.jobs
  retry = worker.jobs[0]
  assert retry.kind == "verify"
  assert retry.retry_count == 1
  assert retry.candidate_message == 8

  worker.jobs.popleft()
  put_inflight(worker, 11, retry)
  worker.update(batch(response(11, KNOWN_CMAC4)), state)
  assert worker.qualified


def test_lat_active_without_request_plane_authority_keeps_warning_asserted():
  worker = ToyotaTss3RequestProxy(Collector(), start_thread=False)
  worker.set_control(True, 0.0)
  assert worker.control_lat_active
  assert not worker.active and not worker.arm_pending
  assert worker.authority_failure_alert_active()

  worker.qualified = True
  worker.arm_pending = True
  assert not worker.authority_failure_alert_active()

  worker.arm_pending = False
  worker.active = True
  assert not worker.authority_failure_alert_active()


def test_brake_state_does_not_duplicate_controlsd_authority_policy():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  qualify(worker, collector)
  assert worker.active and worker.control_lat_active

  before = len(collector.batches)
  # Brake is already part of openpilot's normal engagement/safety path. The
  # proxy must not invent an earlier, second release boundary while the latest
  # CarControl still says latActive=True.
  worker.update([], cs(brake=True))
  assert worker.active
  assert worker.qualified
  assert len(collector.batches) == before

  # controlsd owns the transition. Once CC.latActive falls, the proxy releases
  # the relay exactly once through its normal control boundary.
  worker.set_control(False, 0.0)
  assert not worker.active
  assert collector.batches[-1] == [CanData(ADMIN_ADDR, bytes.fromhex("07c9a80000000000"), ADMIN_BUS)]


def test_native_cruise_latch_does_not_duplicate_controlsd_authority_policy():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  qualify(worker, collector)
  state = cs()
  assert worker.active and worker.control_lat_active

  pending = native_frame(9, 10, target_id=0, angle_raw=100, semantic=0x59, cruise=True)
  worker.update(batch((NATIVE_08A_ADDR, pending, 2)), state)
  assert any(job.kind == "sign" for job in worker.jobs)

  before = len(collector.batches)
  dropped = native_frame(10, 11, target_id=0, angle_raw=100, semantic=0x5A, cruise=False)
  worker.update(batch((NATIVE_08A_ADDR, dropped, 2)), state)

  # The source-real cruise bit is data, not a second engagement state machine.
  # Preserve generation continuity and keep the relay owned until controlsd
  # changes CC.latActive (or Panda rejects a prohibited modified transmission).
  assert worker.active
  assert worker.qualified
  assert collector.batches[before] == [CanData(NATIVE_08A_ADDR, pending, DOWNSTREAM_BUS)]
  assert not any(batch == [CanData(ADMIN_ADDR, bytes.fromhex("07c9a80000000000"), ADMIN_BUS)]
                 for batch in collector.batches[before:])

  worker.set_control(False, 0.0)
  assert not worker.active
  assert collector.batches[-2] == [CanData(NATIVE_08A_ADDR, dropped, DOWNSTREAM_BUS)]
  assert collector.batches[-1] == [CanData(ADMIN_ADDR, bytes.fromhex("07c9a80000000000"), ADMIN_BUS)]


def test_transparent_generation_exports_one_shot_controller_baseline():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  worker.active = True
  worker.control_lat_active = True
  worker.next_output_index = 1

  native_id11 = native_frame(9, 10, target_id=11, angle_raw=123)
  worker.pending_outputs[1] = PendingOutput(native_id11, native_id11, False)
  with worker._cv:
    worker._flush_outputs_locked()
  assert worker.control_target_angle_raw == 123
  assert worker.consume_controller_baseline_angle_deg() == 123 * TSS3_B6_TARGET_ANGLE_SCALE_DEG
  assert worker.consume_controller_baseline_angle_deg() is None

  worker.measured_target_angle_raw = -77
  native_id0 = native_frame(10, 11, target_id=0, angle_raw=400)
  worker.pending_outputs[2] = PendingOutput(native_id0, native_id0, False)
  with worker._cv:
    worker._flush_outputs_locked()
  assert worker.control_target_angle_raw == -77
  assert worker.consume_controller_baseline_angle_deg() == -77 * TSS3_B6_TARGET_ANGLE_SCALE_DEG
  assert worker.consume_controller_baseline_angle_deg() is None


def test_active_non_id11_and_inactive_id11_are_exact_clones():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  qualify(worker, collector)
  state = cs()

  worker.set_control(True, 3.0)
  id18 = native_frame(9, 10, target_id=18, angle_raw=200, semantic=0x59)
  before = len(collector.batches)
  worker.update(batch((NATIVE_08A_ADDR, id18, 2)), state)
  assert collector.batches[before] == [CanData(NATIVE_08A_ADDR, id18, 0)]

  worker.set_control(False, -4.0)
  release_batch_count = len(collector.batches)
  assert collector.batches[-1] == [CanData(ADMIN_ADDR, bytes.fromhex("07c9a80000000000"), ADMIN_BUS)]
  id11 = native_frame(10, 11, target_id=11, angle_raw=300, semantic=0x5A)
  worker.update(batch((NATIVE_08A_ADDR, id11, 2)), state)
  # Stock forwarding owns the path while lateral is inactive; the host emits
  # no exact replacement clone.
  assert len(collector.batches) == release_batch_count
  assert worker.transparent_tx_count == 1


def test_large_native_gap_waits_for_sync_catchup_before_recovery():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  state = cs()

  old_reset = 1109
  new_reset = old_reset + 9
  worker.sync_trip = 620
  worker.sync_reset = old_reset
  seeded = event(1, 26, 100, reset=old_reset)
  assert worker.tracker.seed(seeded, 100)
  worker.last_native_b26 = 26
  worker.stable_native_frames = 100
  worker.qualified = True

  # Exact shape seen on-road: the first post-gap 0x08A arrives before the
  # matching 0x00F catch-up. The 43-count B26 jump invalidates the tracker, but
  # must not immediately start recovery from the stale sync epoch.
  gap = native_frame(5, 143, reset=new_reset, semantic=0x61)
  worker.update(batch((NATIVE_08A_ADDR, gap, 2)), state)
  assert not worker.qualified
  assert not worker.recovery_active
  assert not worker.jobs

  # One more native frame can precede the 0x00F update in the same backlog.
  worker.update(batch((NATIVE_08A_ADDR, native_frame(6, 144, reset=new_reset, semantic=0x62), 2)), state)
  assert not worker.recovery_active

  # Once sync catches up, require ordinary consecutive native cadence before
  # beginning recovery. No guessed forward epoch is needed.
  worker.update(batch((SECOC_SYNC_ADDR, sync_frame(reset=new_reset), 0)), state)
  for b26, message in zip(range(7, 14), range(145, 152), strict=True):
    worker.update(batch((NATIVE_08A_ADDR, native_frame(b26, message, reset=new_reset, semantic=0x63), 2)), state)

  assert worker.recovery_active
  job = worker.jobs[0]
  assert job.kind == "recover"
  assert int.from_bytes(job.domain[32:36], "big") >> 12 == new_reset


def test_sync_ahead_of_native_fv4_signs_the_native_epoch_without_releasing_ownership():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  seq = qualify(worker, collector)
  state = cs()
  worker.set_control(True, 1.0)
  assert worker.active

  old_reset = 1109
  new_reset = old_reset + 1
  # Reproduce the live race: 0x00F has already advanced, but the next native
  # 0x08A still carries the prior reset-low2/FV4. resolve_epoch() must bind this
  # generation to old_reset and keep ownership continuous.
  worker.update(batch((SECOC_SYNC_ADDR, sync_frame(reset=new_reset), 0)), state)
  old_epoch_source = native_frame(9, 10, reset=old_reset, target_id=11, angle_raw=100, semantic=0x59)
  worker.update(batch((NATIVE_08A_ADDR, old_epoch_source, 2)), state)
  assert worker.active
  sign_old = worker.jobs.popleft()
  assert sign_old.kind == "sign"
  assert sign_old.reset_counter == old_reset
  assert sign_old.message_counter == 10
  assert sign_old.domain == build_secoc_domain(sign_old.application, 620, old_reset, 10)

  cmac_old = bytes.fromhex("12345678")
  put_inflight(worker, seq, sign_old)
  worker.update(batch(response(seq, cmac_old)), state)
  sent_old = collector.batches[-1][0].dat
  assert sent_old[28] >> 4 == old_epoch_source[28] >> 4
  assert worker.active
  seq += 1

  # The following native generation moves onto the new reset epoch normally;
  # no ownership release/recovery is needed at the transition.
  new_epoch_source = native_frame(10, 1, reset=new_reset, target_id=11, angle_raw=100, semantic=0x5A)
  worker.update(batch((NATIVE_08A_ADDR, new_epoch_source, 2)), state)
  assert worker.active
  sign_new = worker.jobs.popleft()
  assert sign_new.kind == "sign"
  assert sign_new.reset_counter == new_reset
  assert sign_new.message_counter == 1
  cmac_new = bytes.fromhex("23456789")
  put_inflight(worker, seq, sign_new)
  worker.update(batch(response(seq, cmac_new)), state)
  sent_new = collector.batches[-1][0].dat
  assert sent_new[28] >> 4 == new_epoch_source[28] >> 4
  assert worker.active


def test_active_id0_is_promoted_to_signed_id11_on_same_native_generation():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  seq = qualify(worker, collector)
  state = cs()

  worker.set_control(True, 1.5)
  source = native_frame(9, 10, target_id=0, angle_raw=-120, semantic=0x59)
  before_batches = len(collector.batches)
  worker.update(batch((NATIVE_08A_ADDR, source, 2)), state)
  assert len(collector.batches) == before_batches

  sign = worker.jobs.popleft()
  assert sign.kind == "sign" and sign.native_index == 10 and sign.message_counter == 10
  expected_app = build_id11_application(source[:28], round(1.5 / (1024 / 17870)))
  assert sign.application == expected_app
  assert (sign.application[21] & 0x3F) == 11
  assert sign.application[24] == 100
  for i in range(28):
    if i not in (18, 19, 21, 24):
      assert sign.application[i] == source[i]

  cmac = bytes.fromhex("12345678")
  put_inflight(worker, seq, sign)
  worker.update(batch(response(seq, cmac)), state)
  sent = collector.batches[-1][0].dat
  assert sent == build_signed_frame(expected_app, 1109, 10, cmac)
  assert (sent[21] & 0x3F) == 11
  assert worker.modified_tx_count == 1


def test_active_id11_signs_exact_native_generation_and_preserves_every_other_field():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  seq = qualify(worker, collector)
  state = cs()

  worker.set_control(True, 1.0)
  source = native_frame(9, 10, target_id=11, angle_raw=100, semantic=0x59)
  before_batches = len(collector.batches)
  worker.update(batch((NATIVE_08A_ADDR, source, 2)), state)
  assert len(collector.batches) == before_batches  # waits for command5

  sign = worker.jobs.popleft()
  assert sign.kind == "sign" and sign.native_index == 10 and sign.message_counter == 10
  expected_app = build_id11_application(source[:28], round(1.0 / (1024 / 17870)))
  assert sign.application == expected_app
  # Longitudinal request, ID11/gains and native B26 remain source-real.
  assert sign.application[:18] == source[:18]
  assert sign.application[20:] == source[20:28]

  cmac = bytes.fromhex("12345678")
  put_inflight(worker, seq, sign)
  worker.update(batch(response(seq, cmac)), state)
  sent = collector.batches[-1]
  assert sent == [CanData(NATIVE_08A_ADDR, build_signed_frame(expected_app, 1109, 10, cmac), 0)]
  assert worker.modified_tx_count == 1


def test_new_native_deadline_preserves_order_with_exact_fallback():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  seq = qualify(worker, collector)
  state = cs()

  worker.set_control(True, 2.0)
  first = native_frame(9, 10, target_id=11, angle_raw=100, semantic=0x59)
  worker.update(batch((NATIVE_08A_ADDR, first, 2)), state)
  sign = worker.jobs.popleft()

  # The next native generation is the deadline for the earlier sign. Preserve
  # source order by falling generation 10 back to its exact authenticated frame
  # before the immediately-ready generation 11 crosses downstream.
  second = native_frame(10, 11, target_id=18, angle_raw=400, semantic=0x5A)
  before = len(collector.flat)
  worker.update(batch((NATIVE_08A_ADDR, second, 2)), state)
  assert collector.flat[before:] == [
    CanData(NATIVE_08A_ADDR, first, DOWNSTREAM_BUS),
    CanData(NATIVE_08A_ADDR, second, DOWNSTREAM_BUS),
  ]

  # A late MAC for the already-forwarded generation is consumed as transport
  # completion only; it must not replay the generation as modified ID11.
  put_inflight(worker, seq, sign)
  cmac = bytes.fromhex("23456789")
  before = len(collector.flat)
  worker.update(batch(response(seq, cmac)), state)
  assert len(collector.flat) == before


def test_active_sign_jobs_are_serialized_and_response_driven():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  worker.state_generation = 7
  first = OracleJob(kind="sign", generation=7, domain=KNOWN_DOMAIN, native_index=1,
                    application=KNOWN_APP, trip_counter=620, reset_counter=1109, message_counter=8)
  second = OracleJob(kind="sign", generation=7, domain=KNOWN_DOMAIN, native_index=2,
                     application=KNOWN_APP, trip_counter=620, reset_counter=1109, message_counter=9)
  worker.jobs.extend((first, second))
  worker.next_oracle_send_at = 99.0  # active sign jobs ignore recovery pacing

  with worker._cv:
    item = worker._next_job_locked(1.0)
    assert item is not None and item[1] is first
    assert worker._next_job_locked(1.001) is None
    # Simulate the first private response completing. The next source generation
    # is immediately dispatchable; there is no fixed 25-ms sign cadence.
    worker.inflight.clear()
    item2 = worker._next_job_locked(1.002)
    assert item2 is not None and item2[1] is second


def test_sign_timeout_falls_back_exact_when_newer_source_waits():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  worker.active = True
  worker.qualified = True
  worker.state_generation = 7
  worker.next_output_index = 1

  first_native = native_frame(9, 8, angle_raw=100)
  second_native = native_frame(10, 9, angle_raw=95)
  third_native = native_frame(11, 10, angle_raw=90)
  first = OracleJob(kind="sign", generation=7, domain=KNOWN_DOMAIN, native_index=1,
                    application=KNOWN_APP, trip_counter=620, reset_counter=1109, message_counter=8,
                    sent_at=1.0)
  latest = OracleJob(kind="sign", generation=7, domain=KNOWN_DOMAIN, native_index=3,
                     application=KNOWN_APP, trip_counter=620, reset_counter=1109, message_counter=10)
  worker.pending_outputs[1] = PendingOutput(first_native, None, True)
  # Generation 2 was already superseded before this timeout and therefore has
  # an exact source fallback ready behind generation 1.
  worker.pending_outputs[2] = PendingOutput(second_native, second_native, False)
  worker.pending_outputs[3] = PendingOutput(third_native, None, True)
  worker.inflight[10] = first
  worker.jobs.append(latest)

  with worker._cv:
    worker._expire_inflight_locked(1.046)

  assert worker.active
  assert worker.qualified
  assert not worker.inflight
  assert worker.jobs[0] is latest
  assert 1 not in worker.pending_outputs
  assert 2 not in worker.pending_outputs
  assert worker.next_output_index == 3
  assert collector.batches[-1] == [
    CanData(NATIVE_08A_ADDR, first_native, DOWNSTREAM_BUS),
    CanData(NATIVE_08A_ADDR, second_native, DOWNSTREAM_BUS),
  ]
  assert worker.superseded_sign_count == 1
  assert worker.authority_failure_count == 0
  assert not worker.authority_failure_alert_active()


def test_new_native_falls_back_unsent_generations_and_keeps_latest_sign_job():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  qualify(worker, collector)
  state = cs()

  worker.set_control(True, 2.0)
  first = native_frame(9, 10, target_id=0, angle_raw=100, semantic=0x59)
  worker.update(batch((NATIVE_08A_ADDR, first, 2)), state)
  first_job = worker.jobs.popleft()
  put_inflight(worker, 90, first_job)

  second = native_frame(10, 11, target_id=0, angle_raw=95, semantic=0x5A)
  worker.update(batch((NATIVE_08A_ADDR, second, 2)), state)
  assert len(worker.jobs) == 1 and worker.jobs[0].native_index == 11
  assert collector.flat[-1] == CanData(NATIVE_08A_ADDR, first, DOWNSTREAM_BUS)

  third = native_frame(11, 12, target_id=0, angle_raw=90, semantic=0x5B)
  worker.update(batch((NATIVE_08A_ADDR, third, 2)), state)
  assert len(worker.jobs) == 1 and worker.jobs[0].native_index == 12
  assert collector.flat[-1] == CanData(NATIVE_08A_ADDR, second, DOWNSTREAM_BUS)
  assert 11 not in worker.pending_outputs
  assert worker.superseded_sign_count == 2
  assert worker.authority_failure_count == 0


def test_sign_timeout_retries_twice_before_authority_release():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  worker.active = True
  worker.qualified = True
  worker.state_generation = 7

  job = OracleJob(
    kind="sign", generation=7, domain=KNOWN_DOMAIN, native_index=1,
    application=KNOWN_APP, trip_counter=620, reset_counter=1109, message_counter=8,
    sent_at=1.0,
  )
  worker.inflight[10] = job
  worker.next_oracle_send_at = 99.0

  with worker._cv:
    worker._expire_inflight_locked(1.046)
  assert worker.active
  assert worker.qualified
  assert not worker.inflight
  assert worker.jobs[0] is job
  assert job.retry_count == 1
  assert job.sent_at is None
  assert worker.next_oracle_send_at == 1.046
  assert worker.oracle_timeout_count == 0

  # A second lost response gets one more serialized retry and still preserves
  # the current authority interval.
  worker.jobs.clear()
  job.sent_at = 2.0
  worker.inflight[11] = job
  with worker._cv:
    worker._expire_inflight_locked(2.046)
  assert worker.active
  assert worker.qualified
  assert not worker.inflight
  assert worker.jobs[0] is job
  assert job.retry_count == 2
  assert job.sent_at is None
  assert worker.oracle_timeout_count == 0
  assert worker.authority_failure_count == 0

  # A third consecutive miss is visible, but it is not request-plane loss:
  # the exact source generation is the fallback and relay ownership remains.
  worker.jobs.clear()
  job.sent_at = 3.0
  worker.inflight[12] = job
  with worker._cv:
    worker._expire_inflight_locked(3.046)
  assert worker.active
  assert worker.qualified
  assert worker.oracle_timeout_count == 1
  assert worker.authority_failure_count == 1
  assert worker.last_authority_failure_reason == "oracle_sign_failure"
  assert worker.authority_failure_alert_active()
  assert not collector.flat or collector.flat[-1] != CanData(ADMIN_ADDR, bytes.fromhex("07c9a80000000000"), ADMIN_BUS)


def test_sign_failure_keeps_authority_and_exact_source_fallback():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  seq = qualify(worker, collector)
  state = cs()

  worker.set_control(True, 2.0)
  first = native_frame(9, 10, target_id=11, angle_raw=100, semantic=0x59)
  worker.update(batch((NATIVE_08A_ADDR, first, 2)), state)
  sign = worker.jobs.popleft()
  second = native_frame(10, 11, target_id=18, angle_raw=400, semantic=0x5A)
  before = len(collector.flat)
  worker.update(batch((NATIVE_08A_ADDR, second, 2)), state)
  assert collector.flat[before:] == [
    CanData(NATIVE_08A_ADDR, first, DOWNSTREAM_BUS),
    CanData(NATIVE_08A_ADDR, second, DOWNSTREAM_BUS),
  ]

  put_inflight(worker, seq, sign)
  worker.update(batch(response(seq, b"\x00\x00\x00\x00", status=1)), state)

  # The failed MAC arrived after this generation's exact fallback. It is visible
  # to diagnostics, but it must not tear down the healthy request-plane relay.
  assert worker.active and worker.qualified
  assert worker.authority_failure_count == 1
  assert worker.last_authority_failure_reason == "oracle_sign_failure"
  assert worker.authority_failure_alert_active()
  assert not worker.inflight
  assert all(m.dat != bytes.fromhex("07c9a80000000000") for m in collector.flat[-2:])

  # Non-lateral Toyota applications continue to cross exactly under the same
  # ownership interval; no release/re-arm ceremony is required.
  assert collector.flat[-1] == CanData(NATIVE_08A_ADDR, second, DOWNSTREAM_BUS)
  assert worker.recovery_count == 1


def test_active_host_reject_preserves_qualification_and_rearms_next_native():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  qualify(worker, collector)
  state = cs()
  assert worker.active and worker.qualified

  source = native_frame(9, 10, target_id=0, angle_raw=100, semantic=0x59)
  worker.update(batch((NATIVE_08A_ADDR, source, 2)), state)
  sign = worker.jobs.popleft()
  cmac = bytes.fromhex("12345678")
  signed = build_signed_frame(sign.application, int(sign.reset_counter), int(sign.message_counter), cmac)

  # Simulate Panda rejecting the otherwise attempted host generation.
  worker.update(batch((NATIVE_08A_ADDR, signed, DOWNSTREAM_BUS + PANDA_REJECTED_OFFSET)), state)
  assert not worker.active
  assert worker.qualified
  assert worker.authority_failure_count == 1
  assert worker.last_authority_failure_reason == "host_08a_rejected"
  assert worker.authority_failure_alert_active()

  following = native_frame(10, 11, target_id=0, angle_raw=95, semantic=0x5A)
  worker.update(batch((NATIVE_08A_ADDR, following, 2)), state)
  assert worker.arm_pending
  assert worker.qualified
  assert worker.recovery_count == 1


def test_control_target_can_change_while_sign_job_keeps_native_generation_snapshot():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  qualify(worker, collector)
  state = cs()

  worker.set_control(True, 1.0)
  source = native_frame(9, 10, target_id=11, angle_raw=100)
  worker.update(batch((NATIVE_08A_ADDR, source, 2)), state)
  sign = worker.jobs.popleft()
  signed_angle = sign.application[18:20]
  worker.set_control(True, 5.0)
  assert sign.application[18:20] == signed_angle


def test_request_plane_enable_follows_carparams_topology_flags():
  enabled_safety = SimpleNamespace(safetyParam=(ToyotaSafetyFlags.TSS3_08A_HOST.value |
                                                ToyotaSafetyFlags.TSS3_08A_SIGNED.value))
  cp = SimpleNamespace(carFingerprint=CAR.TOYOTA_CAMRY_TSS3, passive=False, safetyConfigs=[enabled_safety])
  assert request_plane_enabled(cp)

  missing_signed = SimpleNamespace(safetyParam=ToyotaSafetyFlags.TSS3_08A_HOST.value)
  cp_missing = SimpleNamespace(carFingerprint=CAR.TOYOTA_CAMRY_TSS3, passive=False, safetyConfigs=[missing_signed])
  assert not request_plane_enabled(cp_missing)

  passive = SimpleNamespace(carFingerprint=CAR.TOYOTA_CAMRY_TSS3, passive=True, safetyConfigs=[enabled_safety])
  assert not request_plane_enabled(passive)


def test_invalid_carstate_never_qualifies():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  state = cs(valid=False)
  worker.update(batch((SECOC_SYNC_ADDR, sync_frame(), 0)), state)
  for i in range(10):
    worker.update(batch((NATIVE_08A_ADDR, native_frame(i, i + 1), 2)), state)
  assert not worker.active
  assert not worker.qualified
  assert not worker.recovery_active
