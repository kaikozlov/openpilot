from types import SimpleNamespace

from opendbc.car.can_definitions import CanData
from opendbc.car.toyota.values import CAR, ToyotaSafetyFlags
from openpilot.selfdrive.car.toyota_tss3_08a_signed import (
  ADMIN_ADDR, ADMIN_BUS, DOWNSTREAM_BUS, NATIVE_08A_ADDR, PANDA_REJECTED_OFFSET,
  SECOC_SYNC_ADDR,
  ORACLE_BUS,
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


def native_frame(b26: int, message: int, *, reset: int = 1109, target_id: int = 0,
                 angle_raw: int = 0, semantic: int = 0x40, cruise: bool = True) -> bytes:
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
  return bytes(app) + bytes.fromhex(f"{fv4:x}{KNOWN_MAC28}")


def event(index: int, b26: int, message: int, *, reset: int = 1109, target_id: int = 0) -> NativeEvent:
  frame = native_frame(b26, message, reset=reset, target_id=target_id)
  return NativeEvent(index, frame, frame[:28], b26, 620, reset, message & 0x3)


def batch(*frames: tuple[int, bytes, int]):
  return [(1_000_000_000, list(frames))]


def cs(valid: bool = True):
  return SimpleNamespace(canValid=valid)


class Clock:
  def __init__(self): self.now = 0.0
  def __call__(self): return self.now


class Collector:
  def __init__(self): self.batches: list[list[CanData]] = []
  def __call__(self, msgs: list[CanData]): self.batches.append(list(msgs))
  @property
  def flat(self): return [m for b in self.batches for m in b]


def private_response(seq: int, cmac4: bytes = KNOWN_CMAC4, status: int = 0):
  return ORACLE_RESPONSE_ADDR, bytes((0xC9, seq, status, seq ^ 0xFF)) + cmac4, ORACLE_BUS


def seed_at_next_epoch(worker: ToyotaTss3RequestProxy, *, reset: int = 1109, b26: int = 10):
  state = cs()
  worker.update(batch((SECOC_SYNC_ADDR, sync_frame(reset=reset), 0)), state)
  worker.update(batch((NATIVE_08A_ADDR, native_frame(b26, 10, reset=reset), 2)), state)
  assert not worker.freshness_ready
  worker.update(batch((SECOC_SYNC_ADDR, sync_frame(reset=reset + 1), 0)), state)
  worker.update(batch((NATIVE_08A_ADDR, native_frame(b26 + 1, 1, reset=reset + 1), 2)), state)
  assert worker.freshness_ready


def complete_handoff(worker: ToyotaTss3RequestProxy, collector: Collector, *, reset: int = 1110, b26: int = 12):
  state = cs()
  worker.set_control(True, 0.0)
  assert worker.arm_pending
  source = native_frame(b26, 2, reset=reset)
  worker.update(batch((NATIVE_08A_ADDR, source, 2)), state)
  assert collector.flat[-1] == CanData(NATIVE_08A_ADDR, source, DOWNSTREAM_BUS)
  worker.update(batch((NATIVE_08A_ADDR, source, DOWNSTREAM_BUS + 0x80)), state)
  assert worker.active and not worker.arm_pending


def start_active_worker():
  collector = Collector()
  clock = Clock()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False, monotonic=clock)
  seed_at_next_epoch(worker)
  complete_handoff(worker, collector)
  return worker, collector, clock


def test_known_live_domain_and_transport_geometry():
  assert build_secoc_domain(KNOWN_APP, 620, 1109, 8) == KNOWN_DOMAIN
  assert build_signed_frame(KNOWN_APP, 1109, 8, KNOWN_CMAC4).hex() == KNOWN_APP.hex() + "1d64e2a5"
  frames = build_oracle_transport(1, KNOWN_APP, 8, 1109)
  assert len(frames) == 5
  assert all(m.address == 0x1FDC0002 and m.src == ORACLE_BUS and len(m.dat) == 8 for m in frames)
  assert [m.dat[0] for m in frames] == [0x01, 0x21, 0x41, 0x61, 0x81]
  assert b"".join(m.dat[1:] for m in frames[:4]) == KNOWN_APP
  assert frames[4].dat == bytes.fromhex("810855c9a8fe5aa5")


def test_resolve_epoch_nearest_low2():
  assert resolve_epoch(620, 1109, 1109 & 3) == (620, 1109)
  assert resolve_epoch(620, 1109, 1108 & 3) == (620, 1108)
  assert resolve_epoch(620, 1109, 1110 & 3) == (620, 1110)


def test_freshness_waits_for_real_reset_boundary_then_tracks_plus_one():
  tracker = NativeFreshnessTracker()
  ready, lost = tracker.update(event(1, 10, 10, reset=1109))
  assert not ready and not lost
  for i in range(1, 3):
    ready, lost = tracker.update(event(i + 1, 10 + i, 10 + i, reset=1109))
    assert not ready and not lost
  ready, lost = tracker.update(event(4, 13, 1, reset=1110))
  assert ready and not lost and tracker.message_counter == 1
  ready, lost = tracker.update(event(5, 14, 2, reset=1110))
  assert ready and not lost and tracker.message_counter == 2


def test_freshness_gap_drops_ready_state_until_next_reset_boundary():
  tracker = NativeFreshnessTracker()
  tracker.update(event(1, 10, 10, reset=1109))
  tracker.update(event(2, 11, 1, reset=1110))
  assert tracker.ready
  ready, lost = tracker.update(event(3, 13, 3, reset=1110))
  assert not ready and lost
  ready, lost = tracker.update(event(4, 14, 0, reset=1110))
  assert not ready and not lost
  ready, lost = tracker.update(event(5, 15, 1, reset=1111))
  assert ready and not lost and tracker.message_counter == 1


def test_id11_builder_has_only_bounded_lateral_edits():
  for native_id, gain in ((0, 0), (4, 100), (11, 100), (18, 50)):
    app = bytearray(native_frame(4, 5, target_id=native_id)[:28])
    app[24] = gain
    out = build_id11_application(bytes(app), -123)
    assert (out[21] & 0x3F) == 11
    assert out[18:20] == (-123).to_bytes(2, "big", signed=True)
    assert out[24] == (100 if native_id != 11 else gain)
    for i in range(28):
      if i not in (18, 19, 21, 24):
        assert out[i] == app[i]


def test_request_plane_enable_is_topology_flag_only():
  on = SimpleNamespace(carFingerprint=CAR.TOYOTA_CAMRY_TSS3, passive=False,
                       safetyConfigs=[SimpleNamespace(safetyParam=ToyotaSafetyFlags.TSS3_08A_HOST.value)])
  off = SimpleNamespace(carFingerprint=CAR.TOYOTA_CAMRY_TSS3, passive=False,
                        safetyConfigs=[SimpleNamespace(safetyParam=0)])
  assert request_plane_enabled(on)
  assert not request_plane_enabled(off)


def test_proxy_seeds_passively_without_any_oracle_recovery_jobs():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  seed_at_next_epoch(worker)
  assert worker.freshness_ready
  assert not worker.jobs and not worker.inflight
  assert not any(m.address == 0x1FDC0002 for m in collector.flat)


def test_handoff_is_one_exact_source_clone_and_pending_is_unavailable():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  seed_at_next_epoch(worker)
  worker.set_control(True, 0.0)
  assert worker.arm_pending and worker.authority_unavailable()
  first = native_frame(12, 2, reset=1110)
  worker.update(batch((NATIVE_08A_ADDR, first, 2)), cs())
  assert collector.flat[-1] == CanData(NATIVE_08A_ADDR, first, DOWNSTREAM_BUS)
  # A second source before the clone echo aborts; no second Toyota clone is emitted.
  count = sum(m.address == NATIVE_08A_ADDR for m in collector.flat)
  worker.update(batch((NATIVE_08A_ADDR, native_frame(13, 3, reset=1110), 2)), cs())
  assert not worker.active and not worker.arm_pending
  assert sum(m.address == NATIVE_08A_ADDR for m in collector.flat) == count


def test_sign_transport_is_one_stateless_classic_batch():
  worker, collector, clock = start_active_worker()
  source = native_frame(13, 3, reset=1110, target_id=0, angle_raw=10)
  worker.set_control(True, 1.0)
  worker.update(batch((NATIVE_08A_ADDR, source, 2)), cs())
  assert len(worker.jobs) == 1
  with worker._cv:
    seq, job = worker._next_job_locked(clock.now)
  frames = build_oracle_transport(seq, job.application, job.message_counter, job.reset_counter)
  collector(frames)
  assert collector.batches[-1] == frames
  assert len(frames) == 5 and seq in worker.inflight
  assert [m.dat[0] >> 5 for m in frames] == [0, 1, 2, 3, 4]
  assert all(m.address == 0x1FDC0002 and m.src == ORACLE_BUS for m in frames)


def test_sign_response_publishes_same_source_generation():
  worker, collector, clock = start_active_worker()
  worker.set_control(True, 1.0)
  source = native_frame(13, 3, reset=1110, target_id=18, angle_raw=10)
  worker.update(batch((NATIVE_08A_ADDR, source, 2)), cs())
  with worker._cv:
    seq, _ = worker._next_job_locked(clock.now)
  worker.update(batch(private_response(seq)), cs())
  out = collector.batches[-1][0]
  assert out.address == NATIVE_08A_ADDR and out.src == DOWNSTREAM_BUS
  assert (out.dat[21] & 0x3F) == 11 and out.dat[24] == 100
  assert out.dat[26] == source[26]
  assert (out.dat[28] >> 4) == (source[28] >> 4)


def test_out_of_order_oracle_replies_do_not_reorder_08a_outputs():
  worker, collector, clock = start_active_worker()
  worker.set_control(True, 1.0)
  for b26, msg in ((13, 3), (14, 4)):
    worker.update(batch((NATIVE_08A_ADDR, native_frame(b26, msg, reset=1110), 2)), cs())
    with worker._cv:
      seq, job = worker._next_job_locked(clock.now)
    if b26 == 13:
      first = (seq, job)
    else:
      second = (seq, job)
  before = len(collector.batches)
  worker.update(batch(private_response(second[0], bytes.fromhex("12345678"))), cs())
  assert len(collector.batches) == before
  worker.update(batch(private_response(first[0], bytes.fromhex("23456789"))), cs())
  assert len(collector.batches[-1]) == 2
  assert [m.dat[26] & 0x3F for m in collector.batches[-1]] == [13, 14]


def test_response_timeout_allows_live_tail_then_releases_without_generation_fallback():
  worker, _, clock = start_active_worker()
  worker.update(batch((NATIVE_08A_ADDR, native_frame(13, 3, reset=1110), 2)), cs())
  with worker._cv:
    seq, _ = worker._next_job_locked(clock.now)
    clock.now = 0.040
    worker._expire_locked(clock.now)
    assert worker.active and seq in worker.inflight
    clock.now = 0.051
    worker._expire_locked(clock.now)
  assert not worker.active
  assert worker.last_failure_reason == "oracle_response_timeout"
  assert seq not in worker.inflight


def test_brake_or_native_cruise_bits_are_not_proxy_permission_inputs():
  worker, collector, _ = start_active_worker()
  releases_before = sum(m.address == ADMIN_ADDR and m.dat[3] == 0 for m in collector.flat)
  worker.update([], SimpleNamespace(canValid=True, brakePressed=True))
  worker.update(batch((NATIVE_08A_ADDR, native_frame(13, 3, reset=1110, cruise=False), 2)), cs())
  assert worker.active
  assert sum(m.address == ADMIN_ADDR and m.dat[3] == 0 for m in collector.flat) == releases_before
  worker.set_control(False, 0.0)
  assert not worker.active
  assert sum(m.address == ADMIN_ADDR and m.dat[3] == 0 for m in collector.flat) == releases_before + 1
  assert collector.flat[-1] == CanData(ADMIN_ADDR, bytes.fromhex("07c9a80000000000"), ADMIN_BUS)


def test_host_tx_reject_releases_but_does_not_invent_timed_fault_state():
  worker, _, _ = start_active_worker()
  worker.update(batch((NATIVE_08A_ADDR, b"x" * 32, DOWNSTREAM_BUS + PANDA_REJECTED_OFFSET)), cs())
  assert not worker.active
  assert worker.last_failure_reason == ""
  assert worker.authority_unavailable()


def test_invalid_can_releases_and_forgets_freshness():
  worker, _, _ = start_active_worker()
  worker.update([], cs(valid=False))
  assert not worker.active and not worker.freshness_ready
