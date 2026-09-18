from types import SimpleNamespace

from opendbc.car.can_definitions import CanData
from openpilot.selfdrive.car.toyota_tss3_08a import ADMIN_ADDR, ADMIN_BUS, NATIVE_08A_ADDR, SECOC_SYNC_ADDR
from opendbc.car.toyota.values import CAR, ToyotaSafetyFlags
from openpilot.selfdrive.car.toyota_tss3_08a_signed import (
  ORACLE_RESPONSE_ADDR,
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
                 mac28: str = KNOWN_MAC28) -> bytes:
  app = bytearray(KNOWN_APP)
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


def cs(*, valid: bool = True):
  return SimpleNamespace(canValid=valid)


class Collector:
  def __init__(self):
    self.batches: list[list[CanData]] = []

  def __call__(self, msgs: list[CanData]):
    self.batches.append(list(msgs))

  @property
  def flat(self):
    return [m for b in self.batches for m in b]


def response(seq: int, cmac4: bytes, status: int = 0) -> tuple[int, bytes, int]:
  return ORACLE_RESPONSE_ADDR, bytes((0x07, 0xC9, seq, status)) + cmac4, 1


def put_inflight(worker: ToyotaTss3RequestProxy, seq: int, job):
  worker.inflight[seq] = job


def qualify(worker: ToyotaTss3RequestProxy, collector: Collector, *, next_seq: int = 1) -> int:
  state = cs()
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
  assert ff == CanData(0x7A1, bytes.fromhex("1028c9c901008a00"), 1)
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


def test_freshness_tracker_continues_across_reset_progression():
  tracker = NativeFreshnessTracker()
  assert tracker.seed(event(1, 10, 8), 8)
  ok, reset_changed = tracker.update(event(2, 11, 9))
  assert ok and not reset_changed and tracker.message_counter == 9
  ok, reset_changed = tracker.update(event(3, 13, 11))
  assert ok and not reset_changed and tracker.message_counter == 11
  ok, reset_changed = tracker.update(event(4, 14, 12, reset=1110))
  assert ok and reset_changed and tracker.message_counter == 12


def test_id11_builder_changes_only_pinion_angle():
  native = native_frame(4, 5, target_id=11, angle_raw=123, semantic=0x77)[:28]
  modified = build_id11_application(native, -456)
  assert modified[18:20] == (-456).to_bytes(2, "big", signed=True)
  assert modified[:18] == native[:18]
  assert modified[20:] == native[20:]

  non_id11 = native_frame(4, 5, target_id=18)[:28]
  try:
    build_id11_application(non_id11, 0)
  except ValueError:
    pass
  else:
    raise AssertionError("non-ID11 application unexpectedly accepted")


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
  id11 = native_frame(10, 11, target_id=11, angle_raw=300, semantic=0x5A)
  worker.update(batch((NATIVE_08A_ADDR, id11, 2)), state)
  assert collector.batches[-1] == [CanData(NATIVE_08A_ADDR, id11, 0)]
  assert worker.transparent_tx_count == 2


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


def test_output_order_waits_for_earlier_signed_id11():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  seq = qualify(worker, collector)
  state = cs()

  worker.set_control(True, 2.0)
  first = native_frame(9, 10, target_id=11, angle_raw=100, semantic=0x59)
  worker.update(batch((NATIVE_08A_ADDR, first, 2)), state)
  sign = worker.jobs.popleft()

  # A later non-ID11 request is ready immediately, but must not overtake the
  # earlier native generation while its modified ID11 frame is being signed.
  second = native_frame(10, 11, target_id=18, angle_raw=400, semantic=0x5A)
  before = len(collector.batches)
  worker.update(batch((NATIVE_08A_ADDR, second, 2)), state)
  assert len(collector.batches) == before

  put_inflight(worker, seq, sign)
  cmac = bytes.fromhex("23456789")
  worker.update(batch(response(seq, cmac)), state)
  expected_first = build_signed_frame(sign.application, 1109, 10, cmac)
  assert collector.batches[-1] == [CanData(NATIVE_08A_ADDR, expected_first, 0), CanData(NATIVE_08A_ADDR, second, 0)]


def test_sign_failure_flushes_native_frames_then_releases_ownership():
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

  # Fail-open preserves source order with untouched Toyota frames before
  # releasing relay ownership back to normal forwarding.
  assert collector.batches[-2] == [CanData(NATIVE_08A_ADDR, first, 0), CanData(NATIVE_08A_ADDR, second, 0)]
  assert collector.batches[-1] == [CanData(ADMIN_ADDR, bytes.fromhex("07c9a80000000000"), ADMIN_BUS)]
  assert not worker.active and not worker.qualified


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
