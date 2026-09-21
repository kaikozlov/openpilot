from types import SimpleNamespace

import pytest

from opendbc.car import structs
from opendbc.car.can_definitions import CanData
from opendbc.car.secoc import attach_authenticator, build_authentication_data
from opendbc.car.toyota.tss3 import build_host_application
from opendbc.car.toyota.values import CAR, ToyotaSafetyFlags
from openpilot.selfdrive.car.toyota_tss3_08a_signed import (
  ADMIN_ADDR, ADMIN_BUS, DOWNSTREAM_BUS, NATIVE_08A_ADDR, PANDA_REJECTED_OFFSET,
  SECOC_SYNC_ADDR,
  ORACLE_BUS,
  ORACLE_MAX_PENDING_GENERATIONS,
  ORACLE_RESPONSE_ADDR,
  NativeEvent,
  NativeFreshnessTracker,
  ToyotaTss3RequestProxy,
  build_oracle_transport,
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
  return NativeEvent(index, b26, 620, reset, message & 0x3)


def batch(*frames: tuple[int, bytes, int]):
  return [(1_000_000_000, list(frames))]


def cs(valid: bool = True, gas_pressed: bool = False, brake_pressed: bool = False,
       cancel_pressed: bool = False, cruise_enabled: bool = True):
  button_events = [SimpleNamespace(type=structs.CarState.ButtonEvent.Type.cancel, pressed=True)] if cancel_pressed else []
  return SimpleNamespace(canValid=valid, gasPressed=gas_pressed, brakePressed=brake_pressed,
                         buttonEvents=button_events, cruiseState=SimpleNamespace(enabled=cruise_enabled))


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
  worker.set_control(True, True, 0.0, long_active=True, set_speed_kph=70.0)
  assert worker.arm_pending
  source = native_frame(b26, 2, reset=reset)
  worker.update(batch((NATIVE_08A_ADDR, source, 2)), state)
  with worker._cv:
    seq, _ = worker._next_job_locked(worker._monotonic())
  worker.update(batch(private_response(seq)), state)
  host = collector.flat[-1]
  assert host.address == NATIVE_08A_ADDR and host.dat[:28] != source[:28]
  worker.update(batch((NATIVE_08A_ADDR, host.dat, DOWNSTREAM_BUS + 0x80)), state)
  assert worker.active and not worker.arm_pending


def start_active_worker():
  collector = Collector()
  clock = Clock()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False, monotonic=clock)
  seed_at_next_epoch(worker)
  complete_handoff(worker, collector)
  return worker, collector, clock


def test_known_live_domain_and_transport_geometry():
  assert build_authentication_data(0x08A, KNOWN_APP, 620, 1109, 8) == KNOWN_DOMAIN
  assert attach_authenticator(KNOWN_APP, 1109, 8, KNOWN_CMAC4).hex() == KNOWN_APP.hex() + "1d64e2a5"
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


def test_host_builder_owns_complete_active_application():
  out = build_host_application(lat_active=True, target_angle_raw=-123,
                               long_active=True, accel=-0.5,
                               set_speed_kph=70.0, request_sequence=12)
  assert out.hex() == "0000000880002d47fe0c46fe0c7fff007fffff85c00b100064000c00"

  inactive = build_host_application(lat_active=False, target_angle_raw=42,
                                    long_active=False, accel=1.0,
                                    set_speed_kph=70.0, request_sequence=13)
  assert inactive[6:8] == bytes((0x2D, 0x47))
  assert inactive[8:10] == inactive[11:13] == bytes(2)
  assert inactive[18:20] == (42).to_bytes(2, "big", signed=True)
  assert inactive[21] == 0 and inactive[24] == 50

  with pytest.raises(ValueError, match="request sequence"):
    build_host_application(lat_active=True, target_angle_raw=0,
                           long_active=True, accel=0.0,
                           set_speed_kph=0.0, request_sequence=64)


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


def test_handoff_waits_for_first_signed_host_frame_without_cloning_source():
  collector = Collector()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False)
  seed_at_next_epoch(worker)
  worker.set_control(True, True, 0.0, long_active=True)
  assert worker.arm_pending and not worker.authority_unavailable()
  first = native_frame(12, 2, reset=1110)
  worker.update(batch((NATIVE_08A_ADDR, first, 2)), cs())
  assert not any(m.address == NATIVE_08A_ADDR for m in collector.flat)
  # Oracle latency may span more than one source tick without aborting handoff.
  worker.update(batch((NATIVE_08A_ADDR, native_frame(13, 3, reset=1110), 2)), cs())
  assert worker.arm_pending and len(worker.jobs) == 2
  with worker._cv:
    seq, _ = worker._next_job_locked(worker._monotonic())
  worker.update(batch(private_response(seq)), cs())
  host = collector.flat[-1]
  assert host.dat[:28] != first[:28]
  worker.update(batch((NATIVE_08A_ADDR, host.dat, DOWNSTREAM_BUS + 0x80)), cs())
  assert worker.active and not worker.arm_pending


def test_sign_transport_is_one_stateless_classic_batch():
  worker, collector, clock = start_active_worker()
  source = native_frame(13, 3, reset=1110, target_id=0, angle_raw=10)
  worker.set_control(True, True, 1.0)
  worker.update(batch((NATIVE_08A_ADDR, source, 2)), cs())
  assert len(worker.jobs) == 1
  with worker._cv:
    seq, job = worker._next_job_locked(clock.now)
  frames = build_oracle_transport(seq, job.application, job.message_counter, job.reset_counter)
  collector(frames)
  assert collector.batches[-1] == frames
  assert len(frames) == 5 and worker.inflight == (seq, job)
  assert [m.dat[0] >> 5 for m in frames] == [0, 1, 2, 3, 4]
  assert all(m.address == 0x1FDC0002 and m.src == ORACLE_BUS for m in frames)


def test_sign_response_publishes_host_application_on_same_freshness_generation():
  worker, collector, clock = start_active_worker()
  worker.set_control(True, True, 1.0)
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
  assert out.dat[:18] != source[:18]


def test_long_only_control_owns_request_plane_and_replaces_bounds():
  collector = Collector()
  clock = Clock()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False, monotonic=clock)
  seed_at_next_epoch(worker)
  worker.set_control(True, False, 0.0, long_active=True, accel=-0.5)
  assert worker.arm_pending
  handoff = native_frame(12, 2, reset=1110)
  worker.update(batch((NATIVE_08A_ADDR, handoff, 2)), cs())
  with worker._cv:
    handoff_seq, _ = worker._next_job_locked(clock.now)
  worker.update(batch(private_response(handoff_seq)), cs())
  handoff_host = collector.flat[-1].dat
  worker.update(batch((NATIVE_08A_ADDR, handoff_host, DOWNSTREAM_BUS + 0x80)), cs())
  assert worker.active

  source = native_frame(13, 3, reset=1110, target_id=18, angle_raw=10)
  source_app = bytearray(source[:28])
  source_app[6:8] = bytes((0x2D, 0x47))
  source = bytes(source_app) + source[28:]
  worker.update(batch((NATIVE_08A_ADDR, source, 2)), cs())
  with worker._cv:
    seq, job = worker._next_job_locked(clock.now)
  assert job.application[8:10] == (-500).to_bytes(2, "big", signed=True)
  assert job.application[11:13] == (-500).to_bytes(2, "big", signed=True)
  assert job.application[18:20] == bytes(2)
  assert (job.application[21] & 0x3F) == 0
  assert job.application[24] == 50
  worker.update(batch(private_response(seq)), cs())
  assert collector.batches[-1][0].dat[8:10] == (-500).to_bytes(2, "big", signed=True)

  # Gas override keeps the longitudinal session and request-plane handoff, but
  # publishes openpilot's normal inactive acceleration instead of stock DRCC.
  worker.set_control(True, False, 0.0, long_active=False, accel=-0.5)
  assert worker.active and not worker.longitudinal_authority_unavailable()
  inactive_source = native_frame(14, 4, reset=1110, target_id=18, angle_raw=10)
  inactive_app = bytearray(inactive_source[:28])
  inactive_app[6:8] = bytes((0x2C, 0x46))
  inactive_app[8:10] = (714).to_bytes(2, "big", signed=True)
  inactive_app[11:13] = (714).to_bytes(2, "big", signed=True)
  inactive_source = bytes(inactive_app) + inactive_source[28:]
  worker.update(batch((NATIVE_08A_ADDR, inactive_source, 2)), cs(gas_pressed=True))
  with worker._cv:
    _, inactive_job = worker._next_job_locked(clock.now)
  assert inactive_job.application[6:8] == bytes((0x2D, 0x47))
  assert inactive_job.application[8:10] == bytes(2)
  assert inactive_job.application[11:13] == bytes(2)

  worker.set_control(False, False, 0.0)
  assert not worker.active


def test_lat_active_changes_do_not_drop_engagement_owned_authority():
  worker, collector, clock = start_active_worker()
  releases_before = sum(m.address == ADMIN_ADDR and m.dat[3] == 0 for m in collector.flat)
  worker.set_control(True, False, 0.0)
  assert worker.active and not worker.authority_unavailable()

  source = native_frame(13, 3, reset=1110, target_id=11, angle_raw=10)
  worker.update(batch((NATIVE_08A_ADDR, source, 2)), cs())
  with worker._cv:
    _, job = worker._next_job_locked(clock.now)
  assert job.application[18:20] == bytes(2)
  assert (job.application[21] & 0x3F) == 0
  assert job.application[24] == 50

  worker.set_control(False, False, 0.0)
  assert not worker.active
  assert sum(m.address == ADMIN_ADDR and m.dat[3] == 0 for m in collector.flat) == releases_before + 1


def test_single_flight_queues_new_generations_and_ignores_unmatched_replies():
  worker, collector, clock = start_active_worker()
  worker.set_control(True, True, 1.0)
  worker.update(batch((NATIVE_08A_ADDR, native_frame(13, 3, reset=1110), 2)), cs())
  with worker._cv:
    first_seq, first_job = worker._next_job_locked(clock.now)
  worker.update(batch((NATIVE_08A_ADDR, native_frame(14, 4, reset=1110), 2)), cs())
  with worker._cv:
    assert worker._next_job_locked(clock.now) is None

  releases_before = sum(m.address == ADMIN_ADDR and m.dat[3] == 0 for m in collector.flat)
  before = len(collector.batches)
  clock.now = 0.030
  unmatched_seq = (first_seq % 0x1F) + 1
  worker.update(batch(private_response(unmatched_seq, bytes.fromhex("12345678"))), cs())
  assert len(collector.batches) == before
  assert worker.active and worker.inflight == (first_seq, first_job)
  assert sum(m.address == ADMIN_ADDR and m.dat[3] == 0 for m in collector.flat) == releases_before

  worker.update(batch(private_response(first_seq, bytes.fromhex("23456789"))), cs())
  assert collector.batches[-1][0].dat[26] & 0x3F == 13
  with worker._cv:
    second_seq, second_job = worker._next_job_locked(clock.now)
  assert second_job.native_index == first_job.native_index + 1
  worker.update(batch(private_response(second_seq, bytes.fromhex("3456789a"))), cs())
  assert worker.active
  host_b26 = [m.dat[26] & 0x3F for m in collector.flat if m.address == NATIVE_08A_ADDR]
  assert host_b26[-2:] == [13, 14]
  assert sum(m.address == ADMIN_ADDR and m.dat[3] == 0 for m in collector.flat) == releases_before


def test_response_timeout_retries_same_generation_without_releasing():
  worker, collector, clock = start_active_worker()
  worker.update(batch((NATIVE_08A_ADDR, native_frame(13, 3, reset=1110), 2)), cs())
  with worker._cv:
    seq, job = worker._next_job_locked(clock.now)
    clock.now = 0.040
    worker._expire_locked(clock.now)
    assert worker.active and worker.inflight == (seq, job)
    clock.now = 0.051
    worker._expire_locked(clock.now)
  assert worker.active and worker.inflight is None
  assert worker.jobs and worker.jobs[0] is job
  assert worker.last_failure_reason == ""
  assert not any(m.address == ADMIN_ADDR and m.dat[3] == 0 for m in collector.flat)

  with worker._cv:
    retry_seq, retry_job = worker._next_job_locked(clock.now)
  assert retry_job is job and retry_job.attempts == 2
  clock.now = 0.065
  worker.update(batch(private_response(retry_seq)), cs())
  assert worker.active and not worker.authority_unavailable()
  assert collector.batches[-1][0].address == NATIVE_08A_ADDR


def test_late_response_after_retry_cannot_sign_the_current_generation():
  worker, collector, clock = start_active_worker()
  worker.update(batch((NATIVE_08A_ADDR, native_frame(13, 3, reset=1110), 2)), cs())
  with worker._cv:
    old_seq, job = worker._next_job_locked(clock.now)
    clock.now = 0.051
    worker._expire_locked(clock.now)
    retry_seq, retry_job = worker._next_job_locked(clock.now)
  assert retry_job is job and retry_seq != old_seq

  before = len(collector.batches)
  worker.update(batch(private_response(old_seq, bytes.fromhex("11111111"))), cs())
  assert len(collector.batches) == before and worker.inflight == (retry_seq, job)
  worker.update(batch(private_response(retry_seq, bytes.fromhex("22222222"))), cs())
  assert collector.batches[-1][0].address == NATIVE_08A_ADDR
  assert collector.batches[-1][0].dat[28:32].hex()[1:] == "2222222"


def test_pending_generation_bound_releases_authority_before_unbounded_growth():
  worker, _, clock = start_active_worker()
  worker.update(batch((NATIVE_08A_ADDR, native_frame(13, 3, reset=1110), 2)), cs())
  with worker._cv:
    assert worker._next_job_locked(clock.now) is not None
  for offset in range(1, ORACLE_MAX_PENDING_GENERATIONS):
    worker.update(batch((NATIVE_08A_ADDR, native_frame(13 + offset, 3 + offset, reset=1110), 2)), cs())
  assert worker.inflight is not None and len(worker.jobs) == ORACLE_MAX_PENDING_GENERATIONS - 1

  worker.update(batch((NATIVE_08A_ADDR,
                       native_frame(13 + ORACLE_MAX_PENDING_GENERATIONS,
                                    3 + ORACLE_MAX_PENDING_GENERATIONS, reset=1110), 2)), cs())
  assert not worker.active and not worker.arm_pending
  assert worker.last_failure_reason == "oracle_backlog"
  assert worker.inflight is None and not worker.jobs


def test_recorded_latency_shape_and_one_drop_stay_within_four_generations():
  worker, collector, clock = start_active_worker()
  first_output = len([m for m in collector.flat if m.address == NATIVE_08A_ADDR])
  delays = (0.017, 0.024, 0.014, 0.029, 0.018, 0.020, 0.016, 0.030)
  response_queue = []
  next_native = 0.025
  generation = 0
  max_pending = 0
  dropped = False

  while generation < 200 or worker.jobs or worker.inflight is not None or response_queue:
    clock.now += 0.001
    while response_queue and response_queue[0][0] <= clock.now + 1e-12:
      _, seq = response_queue.pop(0)
      worker.update(batch(private_response(seq)), cs())

    if generation < 200 and clock.now >= next_native - 1e-12:
      message = 3 + generation
      worker.update(batch((NATIVE_08A_ADDR,
                           native_frame((13 + generation) & 0x3F, message, reset=1110), 2)), cs())
      generation += 1
      next_native += 0.025

    with worker._cv:
      item = worker._next_job_locked(clock.now)
    if item is not None:
      seq, job = item
      if job.native_index == 67 and job.attempts == 1:
        dropped = True
      else:
        response_queue.append((clock.now + delays[job.native_index % len(delays)], seq))
        response_queue.sort()

    max_pending = max(max_pending, len(worker.jobs) + int(worker.inflight is not None))
    assert clock.now < 7.0

  outputs = [m for m in collector.flat if m.address == NATIVE_08A_ADDR][first_output:]
  assert dropped and worker.active and worker.last_failure_reason == ""
  assert max_pending <= 4
  assert len(outputs) == 200
  assert [m.dat[26] & 0x3F for m in outputs] == [(13 + i) & 0x3F for i in range(200)]


def test_oracle_releases_before_panda_watchdog_deadline():
  worker, _, clock = start_active_worker()
  worker.update(batch((NATIVE_08A_ADDR, native_frame(13, 3, reset=1110), 2)), cs())
  with worker._cv:
    worker._next_job_locked(clock.now)
    clock.now = 0.091
    worker._expire_locked(clock.now)
  assert not worker.active
  assert worker.last_failure_reason == "oracle_dead"
  assert worker.inflight is None


def test_queued_generation_cannot_be_published_after_deadline():
  worker, collector, clock = start_active_worker()
  initial_outputs = sum(m.address == NATIVE_08A_ADDR for m in collector.flat)
  worker.update(batch((NATIVE_08A_ADDR, native_frame(13, 3, reset=1110), 2)), cs())
  with worker._cv:
    seq, _ = worker._next_job_locked(clock.now)
  clock.now = 0.091
  worker.update(batch(private_response(seq)), cs())
  assert not worker.active
  assert worker.last_failure_reason == "oracle_dead"
  assert sum(m.address == NATIVE_08A_ADDR for m in collector.flat) == initial_outputs


def test_oracle_error_status_retries_instead_of_releasing():
  worker, _, clock = start_active_worker()
  worker.update(batch((NATIVE_08A_ADDR, native_frame(13, 3, reset=1110), 2)), cs())
  with worker._cv:
    seq, job = worker._next_job_locked(clock.now)
  clock.now = 0.010
  worker.update(batch(private_response(seq, status=2)), cs())
  assert worker.active and worker.last_failure_reason == ""
  assert worker.jobs and worker.jobs[0] is job


def test_brake_or_native_cruise_bits_are_not_proxy_permission_inputs():
  worker, collector, _ = start_active_worker()
  releases_before = sum(m.address == ADMIN_ADDR and m.dat[3] == 0 for m in collector.flat)
  worker.update([], SimpleNamespace(canValid=True, brakePressed=True))
  worker.update(batch((NATIVE_08A_ADDR, native_frame(13, 3, reset=1110, cruise=False), 2)), cs())
  assert worker.active
  assert sum(m.address == ADMIN_ADDR and m.dat[3] == 0 for m in collector.flat) == releases_before
  worker.set_control(False, False, 0.0)
  assert not worker.active
  assert sum(m.address == ADMIN_ADDR and m.dat[3] == 0 for m in collector.flat) == releases_before + 1
  assert collector.flat[-1] == CanData(ADMIN_ADDR, bytes.fromhex("07c9a80000000000"), ADMIN_BUS)


def test_host_tx_reject_is_an_ordinary_safety_drop_not_authority_loss():
  worker, _, _ = start_active_worker()
  worker.update(batch((NATIVE_08A_ADDR, b"x" * 32, DOWNSTREAM_BUS + PANDA_REJECTED_OFFSET)), cs())
  assert worker.active
  assert worker.last_failure_reason == ""
  assert not worker.authority_unavailable()


def test_invalid_can_releases_and_forgets_freshness():
  worker, _, _ = start_active_worker()
  worker.update([], cs(valid=False))
  assert not worker.active and not worker.freshness_ready
