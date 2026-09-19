from types import SimpleNamespace

from opendbc.car.can_definitions import CanData
from openpilot.selfdrive.car.toyota_tss3_08a import ADMIN_ADDR, ADMIN_BUS, DOWNSTREAM_BUS, NATIVE_08A_ADDR, PANDA_REJECTED_OFFSET, SECOC_SYNC_ADDR
from opendbc.car.toyota.values import CAR, ToyotaSafetyFlags
from openpilot.selfdrive.car.toyota_tss3_08a_signed import (
  ORACLE_BUS,
  ORACLE_RESPONSE_ADDR,
  OracleJob,
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


def cs(*, valid: bool = True, brake: bool = False):
  return SimpleNamespace(canValid=valid, brakePressed=brake)


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

  # The eighth source frame has message8=8 / low2=0. Native MAC equality
  # resolves the full counter; walking the retained source history then directly
  # qualifies the tracker without a redundant second oracle proof.
  for expected_message in (0, 4, 8):
    job = worker.jobs.popleft()
    assert job.candidate_message == expected_message
    put_inflight(worker, next_seq, job)
    cmac = KNOWN_CMAC4 if expected_message == 8 else bytes.fromhex("aaaaaaaa")
    worker.update(batch(response(next_seq, cmac)), state)
    next_seq += 1

  assert worker.qualified and worker.arm_pending
  admin = collector.flat[-1]
  assert admin == CanData(ADMIN_ADDR, bytes.fromhex("07c9a80100000000"), ADMIN_BUS)
  worker.update(batch((ADMIN_ADDR, admin.dat, ADMIN_BUS + 0x80)), state)

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
  ok, reset_changed = tracker.update(event(3, 12, 10))
  assert ok and not reset_changed and tracker.message_counter == 10

  # Source-real Camry behavior: the first 0x08A in a new reset epoch uses
  # full message counter 1, independent of the previous epoch's full counter.
  ok, reset_changed = tracker.update(event(4, 13, 1, reset=1110))
  assert ok and reset_changed and tracker.message_counter == 1
  ok, reset_changed = tracker.update(event(5, 14, 2, reset=1110))
  assert ok and not reset_changed and tracker.message_counter == 2


def test_freshness_tracker_rejects_missed_reset_boundary():
  tracker = NativeFreshnessTracker()
  assert tracker.seed(event(1, 10, 8), 8)
  # If the first observed generation in the new epoch is not low2=1, the
  # boundary was missed and full-counter recovery is required.
  ok, reset_changed = tracker.update(event(2, 11, 3, reset=1110))
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

  for source_id, source_gain in ((4, 100), (18, 50)):
    native_other = bytearray(native_frame(4, 5, target_id=source_id)[:28])
    native_other[24] = source_gain
    modified_other = build_id11_application(bytes(native_other), -12)
    assert (modified_other[21] & 0x3F) == 11
    assert modified_other[18:20] == (-12).to_bytes(2, "big", signed=True)
    assert modified_other[24] == 100
    for i in range(28):
      if i not in (18, 19, 21, 24):
        assert modified_other[i] == native_other[i]


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
  assert worker.qualified and not worker.active and not worker.arm_pending

  worker.set_control(True, 0.0)
  assert worker.arm_pending


def test_recovery_transport_failure_restarts_after_clean_source_gate():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  state = cs()
  worker.update(batch((SECOC_SYNC_ADDR, sync_frame(), 0)), state)
  for i in range(8):
    worker.update(batch((NATIVE_08A_ADDR, native_frame(i, i + 1), 2)), state)
  assert worker.recovery_active and worker.jobs

  job = worker.jobs.popleft()
  put_inflight(worker, 1, job)
  worker.update(batch(response(1, bytes(4), status=1)), state)
  assert not worker.recovery_active
  assert not worker.qualified
  assert not worker.jobs and not worker.inflight
  assert worker.stable_native_frames == 0

  for i in range(7):
    worker.update(batch((NATIVE_08A_ADDR, native_frame(8 + i, 9 + i), 2)), state)
    assert not worker.recovery_active
  worker.update(batch((NATIVE_08A_ADDR, native_frame(15, 16), 2)), state)
  assert worker.recovery_active and worker.jobs


def test_handoff_uses_exactly_one_source_clone():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  qualify(worker, collector)
  worker.set_control(False, 0.0)
  worker.set_control(True, 0.0)
  assert worker.arm_pending

  state = cs()
  first = native_frame(9, 10)
  worker.update(batch((NATIVE_08A_ADDR, first, 2)), state)
  assert worker.arm_pending and worker.arm_clone_frame == first
  clone_count = sum(m.address == NATIVE_08A_ADDR for m in collector.flat)

  # A second native publication before the first clone echo aborts the handoff;
  # it must never cause another Toyota clone to be emitted under relay ownership.
  second = native_frame(10, 11)
  worker.update(batch((NATIVE_08A_ADDR, second, 2)), state)
  assert not worker.arm_pending and not worker.active
  assert sum(m.address == NATIVE_08A_ADDR for m in collector.flat) == clone_count
  assert worker.last_authority_failure_reason == "handoff_source_overrun"


def test_lat_active_without_request_plane_authority_keeps_warning_asserted():
  worker = ToyotaTss3RequestProxy(Collector(), start_thread=False)
  worker.set_control(True, 0.0)
  assert worker.control_lat_active
  assert not worker.active and not worker.arm_pending
  assert worker.authority_unavailable()

  worker.qualified = True
  worker.arm_pending = True
  assert not worker.authority_unavailable()

  worker.arm_pending = False
  worker.active = True
  assert not worker.authority_unavailable()


def test_brake_state_does_not_create_a_second_proxy_authority_boundary():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  qualify(worker, collector)
  assert worker.active and worker.control_lat_active

  before = len(collector.batches)
  # Brake belongs to the normal openpilot engagement/safety path. The request
  # proxy must not independently release while the latest CarControl still says
  # latActive=True.
  worker.update([], cs(brake=True))
  assert worker.active
  assert worker.qualified
  assert len(collector.batches) == before

  worker.set_control(False, 0.0)
  assert not worker.active
  assert collector.batches[-1] == [CanData(ADMIN_ADDR, bytes.fromhex("07c9a80000000000"), ADMIN_BUS)]


def test_native_cruise_latch_is_data_not_proxy_permission_state():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  qualify(worker, collector)
  state = cs()
  assert worker.active

  pending = native_frame(9, 10, target_id=0, angle_raw=100, semantic=0x59, cruise=True)
  worker.update(batch((NATIVE_08A_ADDR, pending, 2)), state)
  queued_before = len(worker.jobs)
  assert queued_before >= 1

  dropped = native_frame(10, 11, target_id=0, angle_raw=100, semantic=0x5A, cruise=False)
  worker.update(batch((NATIVE_08A_ADDR, dropped, 2)), state)

  # The source-side cruise bit does not independently change proxy ownership.
  # controlsd owns the normal latActive transition; Panda remains the TX safety
  # boundary if a command arrives after controls_allowed has already fallen.
  assert worker.active
  assert worker.qualified
  assert len(worker.jobs) == queued_before + 1

  worker.set_control(False, 0.0)
  assert not worker.active
  assert not worker.jobs
  assert not worker.inflight
  assert collector.batches[-1] == [CanData(ADMIN_ADDR, bytes.fromhex("07c9a80000000000"), ADMIN_BUS)]


def test_active_id18_is_replaced_by_id11_and_inactive_uses_stock_forwarding():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  seq = qualify(worker, collector)
  state = cs()

  worker.set_control(True, 3.0)
  id18 = bytearray(native_frame(9, 10, target_id=18, angle_raw=200, semantic=0x59))
  id18[24] = 50
  before = len(collector.batches)
  worker.update(batch((NATIVE_08A_ADDR, bytes(id18), 2)), state)
  assert len(collector.batches) == before
  sign = worker.jobs.popleft()
  assert sign.kind == "sign"
  assert (sign.application[21] & 0x3F) == 11
  assert sign.application[24] == 100
  put_inflight(worker, seq, sign)
  worker.update(batch(response(seq, bytes.fromhex("12345678"))), state)
  assert (collector.batches[-1][0].dat[21] & 0x3F) == 11

  worker.set_control(False, -4.0)
  release_batch_count = len(collector.batches)
  assert collector.batches[-1] == [CanData(ADMIN_ADDR, bytes.fromhex("07c9a80000000000"), ADMIN_BUS)]
  id11 = native_frame(10, 11, target_id=11, angle_raw=300, semantic=0x5A)
  worker.update(batch((NATIVE_08A_ADDR, id11, 2)), state)
  # Stock forwarding owns the path while lateral is inactive; the host emits
  # no replacement frame.
  assert len(collector.batches) == release_batch_count


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


def test_equal_native_id11_still_queues_oracle_signing():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  qualify(worker, collector)
  state = cs()

  source_raw = 100
  worker.set_control(True, source_raw * (1024 / 17870))
  source = native_frame(9, 10, target_id=11, angle_raw=source_raw, semantic=0x59)
  before = len(collector.batches)
  worker.update(batch((NATIVE_08A_ADDR, source, 2)), state)

  # Byte equality with Toyota's request has no authority meaning. The source
  # generation still requires an EPS-oracle signing job and is not emitted as a
  # transparent native frame.
  assert len(collector.batches) == before
  assert worker.jobs
  sign = worker.jobs[-1]
  assert sign.kind == "sign" and sign.native_index == 10
  assert sign.application == source[:28]


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


def test_output_order_waits_for_every_signed_source_generation():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  seq = qualify(worker, collector)
  state = cs()

  worker.set_control(True, 2.0)
  first = native_frame(9, 10, target_id=11, angle_raw=100, semantic=0x59)
  worker.update(batch((NATIVE_08A_ADDR, first, 2)), state)
  sign = worker.jobs.popleft()

  # A later Toyota ID18 owner also becomes comma ID11, but it must not overtake
  # the earlier source generation while that generation is being signed.
  second = bytearray(native_frame(10, 11, target_id=18, angle_raw=400, semantic=0x5A))
  second[24] = 50
  before = len(collector.batches)
  worker.update(batch((NATIVE_08A_ADDR, bytes(second), 2)), state)
  assert len(collector.batches) == before
  second_sign = worker.jobs.popleft()
  assert (second_sign.application[21] & 0x3F) == 11 and second_sign.application[24] == 100

  put_inflight(worker, seq, sign)
  cmac = bytes.fromhex("23456789")
  worker.update(batch(response(seq, cmac)), state)
  expected_first = build_signed_frame(sign.application, 1109, 10, cmac)
  assert collector.batches[-1] == [CanData(NATIVE_08A_ADDR, expected_first, 0)]

  put_inflight(worker, seq + 1, second_sign)
  cmac2 = bytes.fromhex("3456789a")
  worker.update(batch(response(seq + 1, cmac2)), state)
  expected_second = build_signed_frame(second_sign.application, 1109, 11, cmac2)
  assert collector.batches[-1] == [CanData(NATIVE_08A_ADDR, expected_second, 0)]


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


def test_sign_flow_control_triggers_one_same_session_cf_repair_then_failure_releases():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False, monotonic=lambda: 1.020)
  worker.active = True
  worker.qualified = True
  worker.state_generation = 7

  job = OracleJob(
    kind="sign", generation=7, domain=KNOWN_DOMAIN, native_index=1,
    application=KNOWN_APP, trip_counter=620, reset_counter=1109, message_counter=8,
    sent_at=1.0,
  )
  worker.inflight[10] = job

  # Real EPS FC belongs to the sole active sign transaction. It does not create
  # a new FF/sequence; it authorizes one bounded repeat of CF1..CF5.
  worker.update(batch((ORACLE_RESPONSE_ADDR, bytes.fromhex("3000280000000000"), ORACLE_BUS)), cs())
  with worker._cv:
    repair = worker._next_cf_repair_locked(1.020)
    assert repair == (10, job)
    assert job.cf_repair_sent_at == 1.020
    assert worker._next_cf_repair_locked(1.021) is None

    # Repair extends only this same transaction's response deadline.
    worker._expire_inflight_locked(1.044)
    assert worker.active and 10 in worker.inflight
    worker._expire_inflight_locked(1.046)

  assert not worker.active
  assert worker.qualified
  assert worker.oracle_timeout_count == 1
  assert worker.authority_failure_count == 1
  assert worker.last_authority_failure_reason == "oracle_sign_failure"
  assert collector.flat[-1] == CanData(ADMIN_ADDR, bytes.fromhex("07c9a80000000000"), ADMIN_BUS)


def test_sign_response_after_cf_repair_preserves_authority():
  worker = ToyotaTss3RequestProxy(Collector(), start_thread=False)
  worker.active = True
  worker.qualified = True
  worker.state_generation = 7
  frame = native_frame(9, 8, target_id=11)
  worker.next_output_index = 1
  worker.pending_outputs[1] = None
  job = OracleJob(
    kind="sign", generation=7, domain=KNOWN_DOMAIN, native_index=1,
    application=KNOWN_APP, trip_counter=620, reset_counter=1109, message_counter=8,
    sent_at=1.0, flow_control_seen=True,
  )
  worker.inflight[10] = job
  with worker._cv:
    assert worker._next_cf_repair_locked(1.020) == (10, job)
  worker.update(batch(response(10, bytes.fromhex("12345678"))), cs())
  assert worker.active and worker.qualified
  assert not worker.inflight
  assert worker.authority_failure_count == 0


def test_sign_failure_releases_authority_but_preserves_qualification_and_rearms():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  seq = qualify(worker, collector)
  state = cs()

  worker.set_control(True, 2.0)
  first = native_frame(9, 10, target_id=11, angle_raw=100, semantic=0x59)
  worker.update(batch((NATIVE_08A_ADDR, first, 2)), state)
  sign = worker.jobs.popleft()
  second = native_frame(10, 11, target_id=18, angle_raw=400, semantic=0x5A)
  worker.update(batch((NATIVE_08A_ADDR, second, 2)), state)

  put_inflight(worker, seq, sign)
  worker.update(batch(response(seq, b"\x00\x00\x00\x00", status=1)), state)

  # A signing failure ends only the current authority interval. Panda resumes
  # stock forwarding; do not replay stale blocked generations from the host.
  assert collector.batches[-1] == [CanData(ADMIN_ADDR, bytes.fromhex("07c9a80000000000"), ADMIN_BUS)]
  assert not worker.active and worker.qualified
  assert worker.authority_failure_count == 1
  assert worker.last_authority_failure_reason == "oracle_sign_failure"
  assert worker.authority_unavailable()
  assert not worker.jobs and not worker.inflight and not worker.pending_outputs

  # The next source-real generation advances the preserved tracker and begins a
  # fresh atomic handoff without brute-force recovery.
  third = native_frame(11, 12, target_id=0, angle_raw=90, semantic=0x5B)
  worker.update(batch((NATIVE_08A_ADDR, third, 2)), state)
  assert worker.arm_pending
  assert worker.qualified
  assert worker.recovery_count == 1  # only the original startup recovery
  assert collector.flat[-1] == CanData(ADMIN_ADDR, bytes.fromhex("07c9a80100000000"), ADMIN_BUS)


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
  assert worker.authority_failure_count == 0
  assert worker.authority_unavailable()

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


def test_request_plane_enable_follows_carparams_topology_flag():
  enabled_safety = SimpleNamespace(safetyParam=ToyotaSafetyFlags.TSS3_08A_HOST.value)
  cp = SimpleNamespace(carFingerprint=CAR.TOYOTA_CAMRY_TSS3, passive=False, safetyConfigs=[enabled_safety])
  assert request_plane_enabled(cp)

  disabled_safety = SimpleNamespace(safetyParam=0)
  cp_disabled = SimpleNamespace(carFingerprint=CAR.TOYOTA_CAMRY_TSS3, passive=False, safetyConfigs=[disabled_safety])
  assert not request_plane_enabled(cp_disabled)

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
