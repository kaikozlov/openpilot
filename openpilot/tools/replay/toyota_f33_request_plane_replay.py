from __future__ import annotations

import argparse
import heapq
from collections import Counter, defaultdict, deque
from pathlib import Path
from types import SimpleNamespace

from openpilot.tools.lib.logreader import LogReader
from openpilot.selfdrive.car.toyota_tss3_08a_signed import (
  ADMIN_ADDR, NATIVE_08A_ADDR, ORACLE_BUS, ORACLE_REQUEST_ADDR,
  ORACLE_RESPONSE_ADDR, ToyotaTss3RequestProxy, build_oracle_transport,
)

parser = argparse.ArgumentParser(description="Replay the EPS-owned-freshness F33 signer scheduler over recorded timing")
parser.add_argument("route", type=Path)
parser.add_argument("--oracle-response-delay-ms", type=float,
                    help="fixed signer latency; default reuses recorded signer latency samples")
parser.add_argument("--drop-sign-response", type=int, metavar="N")
parser.add_argument("--duplicate-sign-response", type=int, metavar="N")
parser.add_argument("--error-sign-response", type=int, metavar="N")
parser.add_argument("--late-sign-response", type=int, metavar="N")
parser.add_argument("--expect-fail-open", action="store_true")
args = parser.parse_args()


def route_files(path: Path) -> list[Path]:
  if path.is_file():
    return [path]
  files = sorted(path.glob("*/rlog.zst"))
  if not files:
    files = sorted(path.parent.glob(f"{path.name}--*/rlog.zst"))
  return files


files = route_files(args.route)
if not files:
  raise RuntimeError(f"no rlogs under {args.route}")

# The old raw-extended carrier is accepted only as historical latency evidence.
LEGACY_REQUEST_ADDR = 0x1FDC0002
LEGACY_RESPONSE_ADDR = 0x1FE00002
control_events: list[tuple[int, bool, bool, bool, float]] = []
valid_events: list[tuple[int, bool]] = []
request_events: list[tuple[int, int, int]] = []
response_events: list[tuple[int, int, int]] = []
first_ns: int | None = None
last_ns: int | None = None

for path in files:
  for msg in LogReader(str(path), sort_by_time=False):
    t = int(msg.logMonoTime)
    first_ns = t if first_ns is None else min(first_ns, t)
    last_ns = t if last_ns is None else max(last_ns, t)
    which = msg.which()
    if which == "carControl":
      cc = msg.carControl
      control_events.append((t, bool(cc.enabled), bool(cc.latActive), bool(cc.longActive), float(cc.actuators.accel)))
    elif which == "carState":
      valid_events.append((t, bool(msg.carState.canValid)))
    elif which == "sendcan":
      for frame in msg.sendcan:
        address, data, bus = int(frame.address), bytes(frame.dat), int(frame.src)
        if bus != ORACLE_BUS or len(data) != 8:
          continue
        if address == ORACLE_REQUEST_ADDR and data[0] == 0xC8 and (data[1] >> 5) == 0:
          request_events.append((t, data[1] & 0x1F, address))
        elif address == LEGACY_REQUEST_ADDR and (data[0] >> 5) == 0:
          request_events.append((t, data[0] & 0x1F, address))
    elif which == "can":
      for frame in msg.can:
        address, data, bus = int(frame.address), bytes(frame.dat), int(frame.src)
        if bus == ORACLE_BUS and len(data) == 8 and data[0] == 0xC9 and address in (ORACLE_RESPONSE_ADDR, LEGACY_RESPONSE_ADDR):
          response_events.append((t, data[1], address))

if first_ns is None or last_ns is None:
  raise RuntimeError("route contains no timed events")


def recorded_latencies_ms() -> list[float]:
  pending: dict[tuple[int, int], deque[int]] = defaultdict(deque)
  latencies = []
  for t, kind, seq, address in sorted(
    [(t, 0, seq, address) for t, seq, address in request_events] +
    [(t, 1, seq, address) for t, seq, address in response_events]
  ):
    carrier = 0 if address in (ORACLE_REQUEST_ADDR, ORACLE_RESPONSE_ADDR) else 1
    key = (carrier, seq)
    if kind == 0:
      pending[key].append(t)
    elif pending[key]:
      request_t = pending[key].popleft()
      if 0 <= t - request_t < 500_000_000:
        latencies.append((t - request_t) / 1e6)
  return latencies


recorded_latencies = recorded_latencies_ms()
if args.oracle_response_delay_ms is not None:
  latency_samples = [args.oracle_response_delay_ms]
  latency_source = "fixed"
elif recorded_latencies:
  latency_samples = recorded_latencies
  latency_source = "recorded"
else:
  latency_samples = [20.0]
  latency_source = "fallback"

latency_sorted = sorted(latency_samples)
print("route_duration_s", (last_ns - first_ns) / 1e9,
      "control_events", len(control_events), "valid_events", len(valid_events))
print("oracle_timing", latency_source, "samples", len(latency_samples),
      "p50_ms", latency_sorted[len(latency_sorted) // 2],
      "p99_ms", latency_sorted[round((len(latency_sorted) - 1) * 0.99)],
      "max_ms", latency_sorted[-1])

clock = [0.0]
state = SimpleNamespace(canValid=True)
echoes: deque[tuple[int, bytes, int]] = deque()
responses: list[tuple[float, int, int, int]] = []
response_serial = 0
request_count = 0
stats = Counter()
host_times: list[float] = []
publication_latencies_ms: list[float] = []
max_pending = 0
failure_reasons: list[str] = []
current_response_queued_at: float | None = None


def send_can(msgs):
  global current_response_queued_at
  for msg in msgs:
    address, data, bus = int(msg.address), bytes(msg.dat), int(msg.src)
    if address == NATIVE_08A_ADDR:
      host_times.append(clock[0])
      stats["host_publications"] += 1
      if current_response_queued_at is not None:
        publication_latencies_ms.append((clock[0] - current_response_queued_at) * 1000.0)
      echoes.append((address, data, bus + 0x80))
    elif address == ADMIN_ADDR and bus == 1:
      stats["arms" if data[3] else "releases"] += 1
      echoes.append((address, data, bus + 0x80))


proxy = ToyotaTss3RequestProxy(send_can, start_thread=False, monotonic=lambda: clock[0])
original_record_failure = proxy._record_failure_locked


def record_failure(reason: str):
  failure_reasons.append(reason)
  stats[f"failure_{reason}"] += 1
  original_record_failure(reason)


proxy._record_failure_locked = record_failure


def drain_echoes():
  while echoes:
    address, data, src = echoes.popleft()
    proxy.update([(0, [(address, data, src)])], state)


def deliver_responses():
  global current_response_queued_at
  while responses and responses[0][0] <= clock[0] + 1e-12:
    _, _, seq, status = heapq.heappop(responses)
    current_response_queued_at = proxy.inflight[1].queued_at if proxy.inflight is not None and proxy.inflight[0] == seq else None
    trailer = bytes((0x11, 0x23, 0x45, 0x67))
    proxy.update([(0, [(ORACLE_RESPONSE_ADDR, bytes((0xC9, seq, status, seq ^ 0xFF)) + trailer, ORACLE_BUS)])], state)
    current_response_queued_at = None
    drain_echoes()


def run_oracle():
  global request_count, response_serial
  with proxy._cv:
    item = proxy._next_job_locked(clock[0])
  if item is None:
    return
  seq, job = item
  transport = build_oracle_transport(seq, job.application)
  assert len(transport) == 6 and all(frame.address == ORACLE_REQUEST_ADDR for frame in transport)
  request_count += 1
  stats["oracle_requests"] += 1
  if args.drop_sign_response == request_count:
    stats["injected_drops"] += 1
    return
  delay_ms = latency_samples[(request_count - 1) % len(latency_samples)]
  if args.late_sign_response == request_count:
    delay_ms = max(delay_ms, 75.0)
    stats["injected_late_responses"] += 1
  status = 2 if args.error_sign_response == request_count else 0
  if status:
    stats["injected_error_responses"] += 1
  response_serial += 1
  heapq.heappush(responses, (clock[0] + delay_ms / 1000.0, response_serial, seq, status))
  if args.duplicate_sign_response == request_count:
    response_serial += 1
    heapq.heappush(responses, (clock[0] + delay_ms / 1000.0 + 0.001, response_serial, seq, status))
    stats["injected_duplicate_responses"] += 1


def advance(target: float):
  global max_pending
  while clock[0] + 0.001 < target:
    clock[0] += 0.001
    deliver_responses()
    run_oracle()
    drain_echoes()
    max_pending = max(max_pending, len(proxy.jobs) + int(proxy.inflight is not None))
  clock[0] = target
  deliver_responses()
  run_oracle()
  drain_echoes()


timeline = [(t, 0, valid) for t, valid in valid_events]
timeline += [(t, 1, (enabled, lat_active, long_active, accel))
             for t, enabled, lat_active, long_active, accel in control_events]
timeline.sort()
for t, kind, payload in timeline:
  advance((t - first_ns) / 1e9)
  if kind == 0:
    state.canValid = bool(payload)
    proxy.update([], state)
  else:
    enabled, lat_active, long_active, accel = payload
    proxy.set_control(enabled, lat_active, 0.0, long_active=long_active, accel=accel, set_speed_kph=0.0)
  drain_echoes()

advance((last_ns - first_ns) / 1e9 + 0.150)
proxy.set_control(False, False, 0.0)
drain_echoes()

host_gaps_ms = [(b - a) * 1000.0 for a, b in zip(host_times, host_times[1:], strict=False) if b - a < 1.0]
fail_open_count = stats["failure_oracle_backlog"] + stats["failure_oracle_dead"]
print("RESULT", dict(stats), "max_pending", max_pending,
      "max_publication_latency_ms", max(publication_latencies_ms, default=0.0),
      "max_host_gap_ms", max(host_gaps_ms, default=0.0),
      "last_failure", proxy.last_failure_reason)

assert max_pending <= 8, max_pending
if args.expect_fail_open:
  assert fail_open_count > 0, stats
else:
  assert fail_open_count == 0, (stats, failure_reasons)
  assert max(publication_latencies_ms, default=0.0) < 100.0
for option, key in ((args.drop_sign_response, "injected_drops"),
                    (args.duplicate_sign_response, "injected_duplicate_responses"),
                    (args.error_sign_response, "injected_error_responses"),
                    (args.late_sign_response, "injected_late_responses")):
  if option is not None:
    assert stats[key] == 1, (key, stats)
print("PASS F33 EPS-OWNED-FRESHNESS SCHEDULER REPLAY")
