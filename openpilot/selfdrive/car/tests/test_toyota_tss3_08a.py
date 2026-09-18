from types import SimpleNamespace

from opendbc.car import Bus, gen_empty_fingerprint, structs
from opendbc.car.can_definitions import CanData
from opendbc.car.toyota.interface import CarInterface
from opendbc.car.toyota.values import CAR, ToyotaSafetyFlags
from openpilot.selfdrive.car.card import refresh_can_parsers
from openpilot.selfdrive.car.toyota_tss3_08a import (
  ADMIN_ADDR,
  ADMIN_BUS,
  DOWNSTREAM_BUS,
  NATIVE_08A_ADDR,
  SECOC_SYNC_ADDR,
  STABLE_NATIVE_FRAMES,
  ToyotaTss3Id0Proxy,
  decode_sync,
  enable_in_car_params,
  make_admin,
)

GearShifter = structs.CarState.GearShifter


def sync_frame(reset: int = 0x12345, trip: int = 0x026C) -> bytes:
  data = bytearray(8)
  data[0:2] = trip.to_bytes(2, "big")
  data[2] = (reset >> 12) & 0xFF
  data[3] = (reset >> 4) & 0xFF
  data[4] = (reset & 0xF) << 4
  return bytes(data)


def native_08a(b26: int, *, reset: int = 0x12345, target_id: int = 0, semantic: int = 0x22) -> bytes:
  data = bytearray(32)
  data[4] = 0x80
  data[18:20] = b"\x00\x10"
  data[21] = target_id
  data[22] = semantic
  data[26] = b26 & 0x3F
  message_low2 = b26 & 0x3  # only progression matters to the transparent proxy fixture
  fv4 = (message_low2 << 2) | (reset & 0x3)
  data[28] = fv4 << 4
  data[29:32] = b"\x12\x34\x56"
  return bytes(data)


def batch(*frames: tuple[int, bytes, int]):
  return [(1_000_000_000, list(frames))]


def car_state(*, standstill: bool = True, gear=GearShifter.park):
  return SimpleNamespace(canValid=True, standstill=standstill, gearShifter=gear)


class Collector:
  def __init__(self):
    self.batches: list[list[CanData]] = []

  def __call__(self, msgs: list[CanData]):
    self.batches.append(list(msgs))

  @property
  def flat(self):
    return [msg for batch_ in self.batches for msg in batch_]


def prime(proxy: ToyotaTss3Id0Proxy, collector: Collector, *, reset: int = 0x12345):
  cs = car_state()
  proxy.update(batch((SECOC_SYNC_ADDR, sync_frame(reset), 2)), cs)
  for b26 in range(STABLE_NATIVE_FRAMES):
    proxy.update(batch((NATIVE_08A_ADDR, native_08a(b26, reset=reset), 2)), cs)
  assert collector.flat[-1] == make_admin(True)
  assert proxy.arm_pending
  assert not proxy.active


def confirm_arm(proxy: ToyotaTss3Id0Proxy, collector: Collector):
  admin = collector.flat[-1]
  assert admin.address == ADMIN_ADDR
  proxy.update(batch((admin.address, admin.dat, admin.src + 0x80)), car_state())
  assert proxy.arm_pending and proxy.arm_accepted and not proxy.active

  first_owned_b26 = ((proxy.last_b26 or 0) + 1) & 0x3F
  frame = native_08a(first_owned_b26, reset=proxy.reset_counter)
  proxy.update(batch((NATIVE_08A_ADDR, frame, 2)), car_state())
  assert collector.flat[-1] == CanData(NATIVE_08A_ADDR, frame, DOWNSTREAM_BUS)
  proxy.update(batch((NATIVE_08A_ADDR, frame, DOWNSTREAM_BUS + 0x80)), car_state())
  assert proxy.active and not proxy.arm_pending
  return first_owned_b26


def test_sync_decoder():
  assert decode_sync(sync_frame(0xABCDE, 0x1234)) == (0x1234, 0xABCDE)


def test_admin_wire_shape():
  assert make_admin(True) == CanData(ADMIN_ADDR, bytes.fromhex("07c9a80100000000"), ADMIN_BUS)
  assert make_admin(False) == CanData(ADMIN_ADDR, bytes.fromhex("07c9a80000000000"), ADMIN_BUS)


def test_transparent_id0_handoff_and_proxy():
  collector = Collector()
  proxy = ToyotaTss3Id0Proxy(collector)
  prime(proxy, collector)
  confirm_arm(proxy, collector)

  expected = native_08a(STABLE_NATIVE_FRAMES)
  proxy.update(batch((NATIVE_08A_ADDR, expected, 2)), car_state())
  assert collector.flat[-1] == CanData(NATIVE_08A_ADDR, expected, DOWNSTREAM_BUS)
  assert collector.flat[-1].dat == expected
  assert proxy.proxy_count == 2


def test_non_id0_releases_without_proxying():
  collector = Collector()
  proxy = ToyotaTss3Id0Proxy(collector)
  prime(proxy, collector)
  confirm_arm(proxy, collector)
  before = proxy.proxy_count
  proxy.update(batch((NATIVE_08A_ADDR, native_08a(STABLE_NATIVE_FRAMES, target_id=11), 2)), car_state())
  assert not proxy.active
  assert proxy.proxy_count == before
  assert collector.flat[-1] == make_admin(False)


def test_generation_gap_releases_without_proxying():
  collector = Collector()
  proxy = ToyotaTss3Id0Proxy(collector)
  prime(proxy, collector)
  confirm_arm(proxy, collector)
  frame = native_08a(((proxy.last_b26 or 0) + 2) & 0x3F)
  proxy.update(batch((NATIVE_08A_ADDR, frame, 2)), car_state())
  assert proxy.active
  proxy.update(batch((NATIVE_08A_ADDR, frame, DOWNSTREAM_BUS + 0xC0)), car_state())
  assert not proxy.active
  assert collector.flat[-1] == make_admin(False)


def test_motion_releases_and_does_not_proxy():
  collector = Collector()
  proxy = ToyotaTss3Id0Proxy(collector)
  prime(proxy, collector)
  confirm_arm(proxy, collector)
  before = proxy.proxy_count
  proxy.update(batch((NATIVE_08A_ADDR, native_08a((proxy.last_b26 or 0) + 1), 2)), car_state(standstill=False))
  assert not proxy.active
  assert proxy.proxy_count == before
  assert collector.flat[-1] == make_admin(False)


def test_invalid_carstate_releases_and_does_not_proxy():
  collector = Collector()
  proxy = ToyotaTss3Id0Proxy(collector)
  prime(proxy, collector)
  confirm_arm(proxy, collector)
  before = proxy.proxy_count
  invalid = car_state()
  invalid.canValid = False
  proxy.update(batch((NATIVE_08A_ADDR, native_08a((proxy.last_b26 or 0) + 1), 2)), invalid)
  assert not proxy.active
  assert proxy.proxy_count == before
  assert collector.flat[-1] == make_admin(False)


def test_non_park_releases_and_does_not_proxy():
  collector = Collector()
  proxy = ToyotaTss3Id0Proxy(collector)
  prime(proxy, collector)
  confirm_arm(proxy, collector)
  before = proxy.proxy_count
  proxy.update(batch((NATIVE_08A_ADDR, native_08a((proxy.last_b26 or 0) + 1), 2)),
               car_state(gear=GearShifter.drive))
  assert not proxy.active
  assert proxy.proxy_count == before
  assert collector.flat[-1] == make_admin(False)


def test_reset_change_mirrors_safety_release_and_requalifies():
  collector = Collector()
  proxy = ToyotaTss3Id0Proxy(collector)
  prime(proxy, collector)
  confirm_arm(proxy, collector)
  proxy.update(batch((SECOC_SYNC_ADDR, sync_frame(0x12346), 2)), car_state())
  assert not proxy.active
  assert proxy.stable_native_frames == 0
  assert proxy.last_b26 is None
  # Safety independently releases ownership on the reset-counter change.


def test_pending_clone_is_offered_before_ownership_confirmation():
  collector = Collector()
  proxy = ToyotaTss3Id0Proxy(collector)
  prime(proxy, collector)
  admin = collector.flat[-1]
  proxy.update(batch((admin.address, admin.dat, admin.src + 0x80)), car_state())
  assert proxy.arm_accepted and not proxy.active
  b26 = ((proxy.last_b26 or 0) + 1) & 0x3F
  frame = native_08a(b26, reset=proxy.reset_counter)
  proxy.update(batch((NATIVE_08A_ADDR, frame, 2)), car_state())
  assert collector.flat[-1] == CanData(NATIVE_08A_ADDR, frame, DOWNSTREAM_BUS)
  # A pre-ownership rejection is harmless; stock forwarding remains authoritative.
  proxy.update(batch((NATIVE_08A_ADDR, frame, DOWNSTREAM_BUS + 0xC0)), car_state())
  assert proxy.arm_pending and not proxy.active


def test_rejected_proxy_echo_releases():
  collector = Collector()
  proxy = ToyotaTss3Id0Proxy(collector)
  prime(proxy, collector)
  confirm_arm(proxy, collector)
  frame = native_08a(((proxy.last_b26 or 0) + 1) & 0x3F)
  before = proxy.proxy_count
  proxy.update(batch((NATIVE_08A_ADDR, frame, 2)), car_state())
  assert proxy.active and proxy.proxy_count == before + 1
  proxy.update(batch((NATIVE_08A_ADDR, frame, DOWNSTREAM_BUS + 0xC0)), car_state())
  assert not proxy.active
  assert proxy.rejected_proxy_count == 1
  assert collector.flat[-1] == make_admin(False)


def test_bad_reset_low2_never_arms():
  collector = Collector()
  proxy = ToyotaTss3Id0Proxy(collector)
  cs = car_state()
  reset = 0x12345
  proxy.update(batch((SECOC_SYNC_ADDR, sync_frame(reset), 2)), cs)
  for b26 in range(STABLE_NATIVE_FRAMES + 2):
    proxy.update(batch((NATIVE_08A_ADDR, native_08a(b26, reset=reset + 1), 2)), cs)
  assert not proxy.active
  assert proxy.arm_count == 0


def test_enable_is_exact_car_development_only():
  safety = SimpleNamespace(safetyParam=0)
  cp = SimpleNamespace(carFingerprint=CAR.TOYOTA_CAMRY_TSS3, passive=False, safetyConfigs=[safety])
  assert enable_in_car_params(cp, requested=True, is_release=False)
  assert safety.safetyParam & ToyotaSafetyFlags.TSS3_08A_HOST

  safety2 = SimpleNamespace(safetyParam=0)
  cp2 = SimpleNamespace(carFingerprint=CAR.TOYOTA_CAMRY_TSS3, passive=False, safetyConfigs=[safety2])
  assert not enable_in_car_params(cp2, requested=True, is_release=True)
  assert safety2.safetyParam == 0

  safety3 = SimpleNamespace(safetyParam=0)
  cp3 = SimpleNamespace(carFingerprint=CAR.TOYOTA_COROLLA_TSS3, passive=False, safetyConfigs=[safety3])
  assert not enable_in_car_params(cp3, requested=True, is_release=False)
  assert safety3.safetyParam == 0

def test_refresh_can_parsers_switches_exact_camry_to_relay_bus0():
  cp = CarInterface.get_params(CAR.TOYOTA_CAMRY_TSS3, gen_empty_fingerprint(), [], True, False, False)
  ci = CarInterface(cp)
  assert ci.can_parsers[Bus.pt].bus == 1
  cp.safetyConfigs[0].safetyParam |= ToyotaSafetyFlags.TSS3_08A_HOST.value
  refresh_can_parsers(ci, cp)
  assert ci.can_parsers[Bus.pt].bus == 0
