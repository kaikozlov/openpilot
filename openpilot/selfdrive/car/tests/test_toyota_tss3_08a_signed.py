from types import SimpleNamespace

from opendbc.car.can_definitions import CanData
from openpilot.selfdrive.car.toyota_tss3_08a import ADMIN_ADDR, ADMIN_BUS, NATIVE_08A_ADDR, SECOC_SYNC_ADDR
from opendbc.car.toyota.values import CAR, ToyotaSafetyFlags
from openpilot.selfdrive.car.toyota_tss3_08a_signed import (
  ORACLE_RESPONSE_ADDR,
  NativeEvent,
  NativeFreshnessTracker,
  ToyotaTss3SignedId0Proxy,
  build_oracle_transport,
  build_secoc_domain,
  build_signed_frame,
  enable_signed_in_car_params,
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
                 semantic: int = 0x40, mac28: str = KNOWN_MAC28) -> bytes:
  app = bytearray(KNOWN_APP)
  app[21] = 0
  app[22] = semantic
  app[26] = b26 & 0x3F
  fv4 = ((message & 0x3) << 2) | (reset & 0x3)
  trailer = bytes.fromhex(f"{fv4:x}{mac28}")
  return bytes(app) + trailer


def event(index: int, b26: int, message: int, *, trip: int = 620, reset: int = 1109) -> NativeEvent:
  frame = native_frame(b26, message, trip=trip, reset=reset)
  return NativeEvent(index, frame, frame[:28], b26, trip, reset, message & 3, KNOWN_MAC28)


def batch(*frames: tuple[int, bytes, int]):
  return [(1_000_000_000, list(frames))]


def cs():
  from opendbc.car import structs
  return SimpleNamespace(standstill=True, gearShifter=structs.CarState.GearShifter.park)


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


def put_inflight(worker: ToyotaTss3SignedId0Proxy, seq: int, job):
  worker.inflight[seq] = job


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
  assert resolve_epoch(620, 1109, (1108 & 3)) == (620, 1108)
  assert resolve_epoch(620, 1109, (1110 & 3)) == (620, 1110)


def test_freshness_tracker_progression_and_epoch_seed():
  tracker = NativeFreshnessTracker()
  e0 = event(1, 10, 8)
  assert tracker.seed(e0, 8)
  ok, epoch_changed = tracker.update(event(2, 11, 9))
  assert ok and not epoch_changed and tracker.message_counter == 9
  ok, epoch_changed = tracker.update(event(3, 13, 11))
  assert ok and not epoch_changed and tracker.message_counter == 11
  # A newer reset epoch seeds the full message counter from transmitted low2.
  ok, epoch_changed = tracker.update(event(4, 14, 2, reset=1110))
  assert ok and epoch_changed and tracker.message_counter == 2


def test_recovery_verify_lookahead_arm_and_signed_tx():
  collector = Collector()
  worker = ToyotaTss3SignedId0Proxy(collector, start_thread=False)
  state = cs()
  worker.update(batch((SECOC_SYNC_ADDR, sync_frame(), 2)), state)

  # Eight consecutive ID0 native frames qualify source geometry. The eighth is
  # message 8 / low2 0, so recovery candidates are 0,4,8,...
  for i in range(8):
    worker.update(batch((NATIVE_08A_ADDR, native_frame(i, i + 1, semantic=0x50 + i), 2)), state)
  assert worker.recovery_active
  assert len(worker.jobs) == 64

  # Candidate 0 -> miss, 4 -> miss, 8 -> exact native MAC match.
  for seq, expected_message in enumerate((0, 4, 8), start=1):
    job = worker.jobs.popleft()
    assert job.candidate_message == expected_message
    put_inflight(worker, seq, job)
    cmac = KNOWN_CMAC4 if expected_message == 8 else bytes.fromhex("aaaaaaaa")
    worker.update(batch(response(seq, cmac)), state)

  assert worker.tracker.message_counter == 8
  assert not worker.recovery_active
  # Matching recovery cancels stale candidates and puts an exact current-frame
  # verification at the front of the new generation.
  verify = worker.jobs.popleft()
  assert verify.kind == "verify" and verify.candidate_message == 8
  put_inflight(worker, 4, verify)
  worker.update(batch(response(4, KNOWN_CMAC4)), state)
  assert worker.qualified

  # Qualification schedules target n+2: from b26 7/msg8 -> b26 9/msg10.
  sign = next(job for job in worker.jobs if job.kind == "sign")
  assert sign.b26 == 9 and sign.message_counter == 10
  worker.jobs.remove(sign)
  put_inflight(worker, 5, sign)
  future_cmac = bytes.fromhex("12345678")
  worker.update(batch(response(5, future_cmac)), state)
  assert (620, 1109, 10, 9) in worker.signed_cache

  # Native b26 8/msg9 advances the tracker. The cached b26 9/msg10 frame is now
  # exactly next, so host sends the arm admin and waits for Panda TX confirmation.
  worker.update(batch((NATIVE_08A_ADDR, native_frame(8, 9, semantic=0x58), 2)), state)
  admin = collector.flat[-1]
  assert admin.address == ADMIN_ADDR and admin.src == ADMIN_BUS
  assert admin.dat == bytes.fromhex("07c9a80109000000")
  assert worker.arm_pending and not worker.active
  worker.update(batch((ADMIN_ADDR, admin.dat, ADMIN_BUS + 0x80)), state)
  assert worker.active

  # When native b26 9/msg10 arrives, Panda has already suppressed it. The host
  # publishes the pre-signed frame immediately; its application comes from b26 7
  # (two generations old) with only B26 advanced to 9.
  worker.update(batch((NATIVE_08A_ADDR, native_frame(9, 10, semantic=0x59), 2)), state)
  sent = collector.flat[-1]
  assert sent.address == NATIVE_08A_ADDR and sent.src == 0
  expected_app = bytearray(native_frame(7, 8, semantic=0x57)[:28])
  expected_app[26] = 9
  assert sent.dat == build_signed_frame(bytes(expected_app), 1109, 10, future_cmac)
  assert worker.signed_tx_count == 1


def test_cache_miss_falls_back_exact_once_and_releases():
  collector = Collector()
  worker = ToyotaTss3SignedId0Proxy(collector, start_thread=False)
  state = cs()
  worker.stationary_park = True
  worker.sync_trip, worker.sync_reset = 620, 1109
  current = event(1, 20, 8)
  worker.history.append(current)
  worker.tracker.seed(current, 8)
  worker.qualified = True
  worker.active = True
  worker.last_native_b26 = 20
  worker.stable_native_frames = 8

  next_frame = native_frame(21, 9, semantic=0x61)
  worker.update(batch((NATIVE_08A_ADDR, next_frame, 2)), state)
  # First send is exact OEM fallback; second is explicit release admin.
  assert collector.batches[-2] == [CanData(NATIVE_08A_ADDR, next_frame, 0)]
  assert collector.batches[-1] == [CanData(ADMIN_ADDR, bytes.fromhex("07c9a80000000000"), 1)]
  assert worker.transparent_fallback_count == 1
  assert not worker.active and not worker.qualified

def test_signed_enable_is_exact_car_non_release_and_sets_both_safety_flags():
  safety = SimpleNamespace(safetyParam=0)
  cp = SimpleNamespace(carFingerprint=CAR.TOYOTA_CAMRY_TSS3, passive=False, safetyConfigs=[safety])
  assert enable_signed_in_car_params(cp, requested=True, is_release=False)
  assert safety.safetyParam & ToyotaSafetyFlags.TSS3_08A_HOST
  assert safety.safetyParam & ToyotaSafetyFlags.TSS3_08A_SIGNED

  release_safety = SimpleNamespace(safetyParam=0)
  release_cp = SimpleNamespace(carFingerprint=CAR.TOYOTA_CAMRY_TSS3, passive=False, safetyConfigs=[release_safety])
  assert not enable_signed_in_car_params(release_cp, requested=True, is_release=True)
  assert release_safety.safetyParam == 0
