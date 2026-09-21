from types import SimpleNamespace

import pytest

from opendbc.car.can_definitions import CanData
from opendbc.car.toyota.tss3 import build_host_application
from opendbc.car.toyota.values import CAR, ToyotaSafetyFlags
from openpilot.selfdrive.car.toyota_tss3_08a_signed import (
  ADMIN_ADDR, ADMIN_BUS, DOWNSTREAM_BUS, NATIVE_08A_ADDR, ORACLE_BUS,
  ORACLE_MAX_PENDING_GENERATIONS, ORACLE_RESPONSE_ADDR, PANDA_REJECTED_OFFSET,
  ToyotaTss3RequestProxy, build_oracle_transport, request_plane_enabled,
)

KNOWN_APP = bytes.fromhex("0000000080000012ffae00ffae7fff007fff004b0000000000001e00")
KNOWN_TRAILER = bytes.fromhex("1d64e2a5")


def batch(*frames: tuple[int, bytes, int]):
  return [(1_000_000_000, list(frames))]


def cs(valid: bool = True):
  return SimpleNamespace(canValid=valid)


class Clock:
  def __init__(self):
    self.now = 0.0

  def __call__(self):
    return self.now


class Collector:
  def __init__(self):
    self.batches: list[list[CanData]] = []

  def __call__(self, msgs: list[CanData]):
    self.batches.append(list(msgs))

  @property
  def flat(self):
    return [m for messages in self.batches for m in messages]


def private_response(seq: int, trailer: bytes = KNOWN_TRAILER, status: int = 0):
  return ORACLE_RESPONSE_ADDR, bytes((0xC9, seq, status, seq ^ 0xFF)) + trailer, ORACLE_BUS


def start_worker(*, complete_handoff: bool = True):
  collector = Collector()
  clock = Clock()
  worker = ToyotaTss3RequestProxy(collector, start_thread=False, monotonic=clock)
  worker.update([], cs())
  worker.set_control(True, True, 0.0, long_active=True, set_speed_kph=70.0)
  assert worker.arm_pending
  with worker._cv:
    seq, _ = worker._next_job_locked(clock.now)
  worker.update(batch(private_response(seq)), cs())
  host = collector.flat[-1]
  if complete_handoff:
    worker.update(batch((NATIVE_08A_ADDR, host.dat, DOWNSTREAM_BUS + 0x80)), cs())
    assert worker.active and not worker.arm_pending
  return worker, collector, clock


def next_job(worker: ToyotaTss3RequestProxy, clock: Clock):
  with worker._cv:
    item = worker._next_job_locked(clock.now)
  assert item is not None
  return item


def test_transport_is_six_application_only_fragments():
  frames = build_oracle_transport(1, KNOWN_APP)
  assert len(frames) == 6
  assert all(m.address == 0x777 and m.src == ORACLE_BUS and len(m.dat) == 8 for m in frames)
  assert [m.dat[:2] for m in frames] == [bytes((0xC8, (i << 5) | 1)) for i in range(6)]
  assert b"".join(m.dat[2:7] for m in frames) == KNOWN_APP + b"\0\0"
  assert all(m.dat[7] == 0 for m in frames)
  with pytest.raises(ValueError, match="28 bytes"):
    build_oracle_transport(1, b"short")


def test_host_builder_owns_complete_application():
  out = build_host_application(lat_active=True, target_angle_raw=-123,
                               long_active=True, accel=-0.5,
                               set_speed_kph=70.0, request_sequence=12)
  assert out.hex() == "0000000880002d47fe0c46fe0c7fff007fffff85c00b100064000c00"

  inactive = build_host_application(lat_active=False, target_angle_raw=42,
                                    long_active=False, accel=1.0,
                                    set_speed_kph=70.0, request_sequence=13)
  assert inactive[8:10] == inactive[11:13] == bytes(2)
  assert inactive[18:20] == (42).to_bytes(2, "big", signed=True)
  assert inactive[21] == 0 and inactive[24] == 50


def test_request_plane_enable_is_topology_flag_only():
  on = SimpleNamespace(carFingerprint=CAR.TOYOTA_CAMRY_TSS3, passive=False,
                       safetyConfigs=[SimpleNamespace(safetyParam=ToyotaSafetyFlags.TSS3_08A_HOST.value)])
  off = SimpleNamespace(carFingerprint=CAR.TOYOTA_CAMRY_TSS3, passive=False,
                        safetyConfigs=[SimpleNamespace(safetyParam=0)])
  assert request_plane_enabled(on)
  assert not request_plane_enabled(off)


def test_arm_and_first_job_need_no_native_or_sync_input():
  worker, collector, _ = start_worker(complete_handoff=False)
  assert worker.arm_pending and not worker.authority_unavailable()
  assert not any(m.src == 2 for m in collector.flat)
  assert collector.flat[-1].address == NATIVE_08A_ADDR


def test_eps_trailer_is_forwarded_without_host_freshness_processing():
  worker, collector, _ = start_worker(complete_handoff=False)
  host = collector.flat[-1]
  assert host.dat[:28] == build_host_application(lat_active=True, target_angle_raw=0,
                                                 long_active=True, accel=0.0,
                                                 set_speed_kph=70.0, request_sequence=0)
  assert host.dat[28:] == KNOWN_TRAILER
  worker.update(batch((NATIVE_08A_ADDR, host.dat, DOWNSTREAM_BUS + 0x80)), cs())
  assert worker.active


def test_periodic_jobs_use_local_sequence_and_latest_control():
  worker, _, clock = start_worker()
  worker.set_control(True, True, 1.0, long_active=True, accel=-0.5, set_speed_kph=71.0)
  clock.now = 0.025
  _, first = next_job(worker, clock)
  assert first.application[26] == 1
  assert first.application[8:10] == (-500).to_bytes(2, "big", signed=True)

  worker.update(batch(private_response(worker.inflight[0])), cs())
  clock.now = 0.050
  _, second = next_job(worker, clock)
  assert second.application[26] == 2
  assert second.publication_index == first.publication_index + 1


def test_native_and_sync_frames_do_not_schedule_or_modify_jobs():
  worker, _, clock = start_worker()
  clock.now = 0.010
  fake_native = bytes(range(32))
  fake_sync = bytes(range(8))
  worker.update(batch((NATIVE_08A_ADDR, fake_native, 2), (0x00F, fake_sync, 0)), cs())
  with worker._cv:
    assert worker._next_job_locked(clock.now) is None
  assert not worker.jobs and worker.inflight is None


def test_single_flight_ignores_unmatched_response():
  worker, collector, clock = start_worker()
  clock.now = 0.025
  seq, job = next_job(worker, clock)
  before = len(collector.batches)
  worker.update(batch(private_response((seq % 0x1F) + 1, bytes.fromhex("12345678"))), cs())
  assert len(collector.batches) == before
  assert worker.inflight == (seq, job)

  worker.update(batch(private_response(seq, bytes.fromhex("23456789"))), cs())
  assert collector.flat[-1].dat[28:] == bytes.fromhex("23456789")


def test_response_timeout_retries_same_application_with_new_transaction():
  worker, collector, clock = start_worker()
  clock.now = 0.025
  old_seq, job = next_job(worker, clock)
  clock.now = 0.076
  with worker._cv:
    worker._expire_locked(clock.now)
    retry_seq, retry_job = worker._next_job_locked(clock.now)
  assert retry_job is job and retry_job.application == job.application
  assert retry_seq != old_seq and retry_job.attempts == 2

  before = len(collector.batches)
  worker.update(batch(private_response(old_seq)), cs())
  assert len(collector.batches) == before
  worker.update(batch(private_response(retry_seq, bytes.fromhex("abcdef01"))), cs())
  assert collector.flat[-1].dat[28:] == bytes.fromhex("abcdef01")


def test_oracle_error_status_retries_instead_of_releasing():
  worker, _, clock = start_worker()
  clock.now = 0.025
  seq, job = next_job(worker, clock)
  clock.now = 0.035
  worker.update(batch(private_response(seq, status=2)), cs())
  assert worker.active and worker.last_failure_reason == ""
  assert worker.jobs and worker.jobs[0] is job


def test_deadline_releases_before_panda_watchdog():
  worker, _, clock = start_worker()
  clock.now = 0.025
  next_job(worker, clock)
  clock.now = 0.116
  with worker._cv:
    worker._expire_locked(clock.now)
  assert not worker.active and not worker.arm_pending
  assert worker.last_failure_reason == "oracle_dead"


def test_backlog_is_bounded_and_fails_open():
  worker, _, clock = start_worker()
  clock.now = 0.025
  next_job(worker, clock)
  clock.now += 0.025 * ORACLE_MAX_PENDING_GENERATIONS
  with worker._cv:
    worker._schedule_due_locked(clock.now)
  assert not worker.active and not worker.arm_pending
  assert worker.last_failure_reason == "oracle_backlog"
  assert not worker.jobs and worker.inflight is None


def test_recorded_latency_shape_and_one_drop_publish_every_period():
  worker, collector, clock = start_worker()
  first_output = sum(m.address == NATIVE_08A_ADDR for m in collector.flat)
  delays = (0.017, 0.024, 0.014, 0.029, 0.018, 0.020, 0.016, 0.030)
  responses: list[tuple[float, int]] = []
  dropped = False
  max_pending = 0

  while clock.now < 5.0 or worker.jobs or worker.inflight is not None or responses:
    clock.now += 0.001
    while responses and responses[0][0] <= clock.now + 1e-12:
      _, seq = responses.pop(0)
      worker.update(batch(private_response(seq)), cs())

    with worker._cv:
      item = worker._next_job_locked(clock.now)
    if item is not None:
      seq, job = item
      if job.publication_index == 67 and job.attempts == 1:
        dropped = True
      else:
        responses.append((clock.now + delays[job.publication_index % len(delays)], seq))
        responses.sort()

    max_pending = max(max_pending, len(worker.jobs) + int(worker.inflight is not None))
    if clock.now >= 5.0 and worker.next_publication_at is not None:
      # Stop creating new jobs, then drain the bounded pipeline.
      worker.next_publication_at = None
    assert clock.now < 6.0

  outputs = [m for m in collector.flat if m.address == NATIVE_08A_ADDR][first_output:]
  assert dropped and worker.active and worker.last_failure_reason == ""
  assert max_pending <= 4
  assert len(outputs) == 200
  assert [m.dat[26] for m in outputs] == [i & 0x3F for i in range(1, 201)]


def test_disable_and_invalid_can_release_authority():
  worker, collector, _ = start_worker()
  worker.update(batch((NATIVE_08A_ADDR, b"x" * 32, DOWNSTREAM_BUS + PANDA_REJECTED_OFFSET)), cs())
  assert worker.active and worker.last_failure_reason == ""

  worker.update([], cs(valid=False))
  assert not worker.active
  assert collector.flat[-1] == CanData(ADMIN_ADDR, bytes.fromhex("07c9a80000000000"), ADMIN_BUS)

  worker.update([], cs())
  assert worker.arm_pending
  worker.set_control(False, False, 0.0)
  assert not worker.arm_pending
