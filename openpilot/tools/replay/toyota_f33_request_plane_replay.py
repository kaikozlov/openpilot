from __future__ import annotations

import argparse
import heapq
from bisect import bisect_right
from collections import Counter, defaultdict, deque
from pathlib import Path
from types import SimpleNamespace

from openpilot.tools.lib.logreader import LogReader
from opendbc.car import structs
from opendbc.car.toyota.interface import CarInterface
from opendbc.car.toyota.values import CAR, EPS_SCALE, ToyotaSafetyFlags
from opendbc.safety.tests.libsafety import libsafety_py
from openpilot.selfdrive.car.toyota_tss3_08a_signed import (
  decode_sync,
  DOWNSTREAM_BUS,
  NATIVE_08A_ADDR,
  ORACLE_BUS,
  ORACLE_REQUEST_ADDR,
  ORACLE_RESPONSE_ADDR,
  SECOC_SYNC_ADDR,
  UPSTREAM_BUS,
  ToyotaTss3RequestProxy,
  build_oracle_transport,
  resolve_epoch,
)

parser = argparse.ArgumentParser(description="Replay F33 native inputs through current controller, signer adapter, and Panda safety")
parser.add_argument("route", type=Path)
parser.add_argument("--oracle-response-delay-ms", type=float,
                    help="fixed signer latency; default reuses recorded raw-oracle latency samples")
parser.add_argument("--drop-sign-response", type=int, metavar="N", help="drop the Nth sign response to exercise fail-open/re-arm")
parser.add_argument("--duplicate-sign-response", type=int, metavar="N", help="duplicate the Nth sign response")
parser.add_argument("--error-sign-response", type=int, metavar="N", help="return an error for the Nth sign response")
parser.add_argument("--late-sign-response", type=int, metavar="N", help="delay the Nth sign response past the retry deadline")
parser.add_argument("--expect-fail-open", action="store_true",
                    help="require backlog/deadline fail-open instead of uninterrupted publication")
parser.add_argument("--scheduler-only", action="store_true",
                    help="exercise only the production signer scheduler over all native generations")
args = parser.parse_args()
files = sorted(args.route.glob('*/rlog.zst'), key=lambda p: int(p.parent.name.rsplit('--', 1)[1]))
if not files:
  files = sorted(args.route.parent.glob(f'{args.route.name}--*/rlog.zst'),
                 key=lambda p: int(p.parent.name.rsplit('--', 1)[1]))
if args.route.is_file():
  files = [args.route]
if not files:
  raise RuntimeError(f"no rlogs under {args.route}")

# Extract only native CAN + recorded CarControl. Old host traffic is evidence for
# truth anchors only; it is never fed back into the current implementation.
events = []
cp_bytes = None
sync_seq = []
native_seq = []
recorded_oracle_tx = []
recorded_oracle_rx = []
recorded_raw_oracle_tx = []
recorded_raw_oracle_rx = []
HISTORICAL_ORACLE_REQUEST_ADDR = 0x7A1
HISTORICAL_ORACLE_RESPONSE_ADDR = 0x7A9
order = 0
for f in files:
  for m in LogReader(str(f), sort_by_time=False):
    t = int(m.logMonoTime)
    if m.which() == 'carParams' and cp_bytes is None:
      cp_bytes = m.carParams.as_builder().to_bytes()
    elif m.which() == 'can':
      for x in m.can:
        d, a, s = bytes(x.dat), int(x.address), int(x.src)
        if a == HISTORICAL_ORACLE_RESPONSE_ADDR and s == ORACLE_BUS and len(d) == 8 and d[:2] == b'\x07\xc9':
          recorded_oracle_rx.append((t, d))
        elif a == ORACLE_RESPONSE_ADDR and s == ORACLE_BUS and len(d) == 8 and d[0] == 0xC9:
          recorded_raw_oracle_rx.append((t, d))
      frames = [(int(x.address), bytes(x.dat), int(x.src)) for x in m.can
                if int(x.src) < 128 and int(x.address) not in (HISTORICAL_ORACLE_RESPONSE_ADDR, ORACLE_RESPONSE_ADDR) and
                not (int(x.address) == NATIVE_08A_ADDR and int(x.src) != UPSTREAM_BUS) and
                not (int(x.address) == 0x412 and int(x.src) == DOWNSTREAM_BUS)]
      if frames:
        events.append((t, 0, order, 'can', frames))
        order += 1
        for a, d, s in frames:
          if a == 0x00F and s == 0 and len(d) == 8:
            sync_seq.append((t, order, d))
          elif a == NATIVE_08A_ADDR and s == 2 and len(d) == 32:
            native_seq.append((t, order, d))
    elif m.which() == 'sendcan':
      for x in m.sendcan:
        if int(x.address) == HISTORICAL_ORACLE_REQUEST_ADDR and int(x.src) == ORACLE_BUS and len(x.dat) == 8:
          recorded_oracle_tx.append((t, bytes(x.dat)))
        elif int(x.address) == ORACLE_REQUEST_ADDR and int(x.src) == ORACLE_BUS and len(x.dat) == 8:
          recorded_raw_oracle_tx.append((t, bytes(x.dat)))
    elif m.which() == 'carControl':
      events.append((t, 1, order, 'cc', m.carControl.as_builder().to_bytes()))
      order += 1
if cp_bytes is None:
  raise RuntimeError('missing CarParams')
events.sort()
sync_seq.sort()
native_seq.sort()

# Independent full-message truth. Within each resolved reset epoch, native F33
# begins at message counter 1 and advances with B26. Hardware-recorded oracle
# responses below independently anchor this reconstruction.
sts = [x[0] for x in sync_seq]
epoch_by_frame = {}
epoch_groups = {}
epoch_order = []
for t, ord_, d in native_seq:
  j = bisect_right(sts, t) - 1
  if j < 0:
    continue
  trip, reset = decode_sync(sync_seq[j][2])
  ep = resolve_epoch(trip, reset, (d[28] >> 4) & 3)
  if ep is None:
    continue
  epoch_by_frame[d] = ep
  if ep not in epoch_groups:
    epoch_groups[ep] = []
    epoch_order.append(ep)
  epoch_groups[ep].append((t, ord_, d))

truth_by_frame = {}
truth_ambiguous = []
for ep in epoch_order:
  rows = epoch_groups[ep]
  candidates = []
  for _, _, start in rows:
    if ((start[28] >> 6) & 3) != 1:
      continue
    sb = start[26] & 0x3F
    seen, distances, ok = set(), [], True
    for _, _, d in rows:
      dist = ((d[26] & 0x3F) - sb) & 0x3F
      if dist in seen or dist > 31 or ((dist + 1) & 3) != ((d[28] >> 6) & 3):
        ok = False
        break
      seen.add(dist)
      distances.append(dist)
    if ok:
      candidates.append((max(distances), sb))
  if not candidates:
    truth_ambiguous.append((ep, 'none'))
    continue
  candidates.sort()
  if len(candidates) > 1 and candidates[1][0] == candidates[0][0]:
    truth_ambiguous.append((ep, 'tie'))
    continue
  sb = candidates[0][1]
  for _, _, d in rows:
    truth_by_frame[d] = (((d[26] & 0x3F) - sb) & 0x3F) + 1

# Validate independent truth against retained real EPS oracle responses.
def mac28(frame: bytes) -> str:
  return frame[28:32].hex()[1:]

recorded_requests = []
i = 0
recorded_oracle_tx.sort()
while i < len(recorded_oracle_tx):
  t, frame = recorded_oracle_tx[i]
  if frame[:2] != b'\x10\x28':
    i += 1
    continue
  nsdu = bytearray(frame[2:])
  j = i + 1
  sn = 1
  while j < len(recorded_oracle_tx) and len(nsdu) < 40 and recorded_oracle_tx[j][1][0] == (0x20 | sn):
    nsdu.extend(recorded_oracle_tx[j][1][1:])
    sn += 1
    j += 1
  if len(nsdu) >= 40:
    nsdu = bytes(nsdu[:40])
    if nsdu[:2] == b'\xc9\xc9' and nsdu[39] == (nsdu[2] ^ 0xFF):
      recorded_requests.append((t, nsdu[2], nsdu[3:39]))
  i = max(i + 1, j)
responses_by_seq = defaultdict(list)
for t, frame in recorded_oracle_rx:
  responses_by_seq[frame[2]].append((t, frame))
native_by_application = defaultdict(list)
for _, _, d in native_seq:
  if d in epoch_by_frame:
    native_by_application[d[:28]].append(d)
anchor_count = 0
for t, seq, domain in recorded_requests:
  response = next((frame for rt, frame in responses_by_seq[seq] if rt >= t and rt - t < 500_000_000), None)
  if response is None:
    continue
  packed = int.from_bytes(domain[32:36], 'big')
  ep = (int.from_bytes(domain[30:32], 'big'), (packed >> 12) & 0xFFFFF)
  candidate = (packed >> 4) & 0xFF
  cmac28 = response[4:8].hex()[:7]
  for d in native_by_application.get(domain[2:30], []):
    if epoch_by_frame.get(d) == ep and mac28(d) == cmac28 and d in truth_by_frame:
      anchor_count += 1
      assert truth_by_frame[d] == candidate, (truth_by_frame[d], candidate)
      break

# Modern residents use five raw classic frames instead of ISO-TP. Reassemble
# retained transactions, pair their replies, and independently anchor the
# freshness counter against the native B26/FV4 progression above.
recorded_raw_requests = []
i = 0
recorded_raw_oracle_tx.sort()
while i < len(recorded_raw_oracle_tx):
  t, first = recorded_raw_oracle_tx[i]
  seq = first[0] & 0x1F
  if (first[0] >> 5) != 0 or seq == 0:
    i += 1
    continue
  batch = recorded_raw_oracle_tx[i:i + 5]
  if len(batch) == 5 and all((frame[0] >> 5) == fragment and (frame[0] & 0x1F) == seq
                             for fragment, (_, frame) in enumerate(batch)):
    application = b''.join(frame[1:] for _, frame in batch[:4])
    tail = batch[4][1]
    if tail[3:] == bytes((0xC9, 0xA8, seq ^ 0xFF, 0x5A, 0xA5)):
      recorded_raw_requests.append((t, seq, application, tail[1], tail[2]))
      i += 5
      continue
  i += 1

raw_latency_ms = []
raw_replied_requests = set()
raw_anchor_mismatches = 0
pending_raw = defaultdict(list)
raw_events = [(t, 0, seq, index) for index, (t, seq, *_rest) in enumerate(recorded_raw_requests)]
raw_events += [(t, 1, frame[1], index) for index, (t, frame) in enumerate(recorded_raw_oracle_rx)]
for t, kind, seq, index in sorted(raw_events):
  if kind == 0:
    pending_raw[seq].append((t, index))
  else:
    while pending_raw[seq] and t - pending_raw[seq][0][0] >= 500_000_000:
      pending_raw[seq].pop(0)
  if kind == 1 and pending_raw[seq]:
    request_t, request_index = pending_raw[seq].pop(0)
    if 0 <= t - request_t < 500_000_000:
      raw_latency_ms.append((t - request_t) / 1e6)
      raw_replied_requests.add(request_index)

for request_index, (t, _seq, application, message_counter, reset_low8) in enumerate(recorded_raw_requests):
  if request_index not in raw_replied_requests:
    continue
  sync_index = bisect_right(sts, t) - 1
  if sync_index < 0:
    continue
  sync_trip, sync_reset = decode_sync(sync_seq[sync_index][2])
  ep = resolve_epoch(sync_trip, sync_reset, reset_low8 & 0x3)
  if ep is None or (ep[1] & 0xFF) != reset_low8:
    continue
  candidates = [
    d for native_t, _, d in epoch_groups.get(ep, [])
    if 0 <= t - native_t < 100_000_000 and (d[26] & 0x3F) == (application[26] & 0x3F) and
       ((d[28] >> 6) & 0x3) == (message_counter & 0x3) and d in truth_by_frame
  ]
  if candidates:
    if any(truth_by_frame[d] == message_counter for d in candidates):
      anchor_count += 1
    else:
      # Retried historical jobs can cross a reset-boundary observation window.
      # They remain useful latency samples but are not freshness anchors.
      raw_anchor_mismatches += 1

if anchor_count == 0:
  raise RuntimeError('no retained hardware oracle anchors')

# Start before the second complete epoch so the new runtime must passively seed
# itself from a real epoch boundary; no synthetic recovery is provided.
if len(epoch_order) < 2:
  raise RuntimeError('route has fewer than two resolved epochs')
truth_boundary = min(t for t, _, _ in epoch_groups[epoch_order[1]])
pre_sync = [t for t, _, _ in sync_seq if t <= truth_boundary]
replay_floor = max(pre_sync) if pre_sync else truth_boundary
events = [e for e in events if e[0] >= replay_floor]
start_ns, end_ns = events[0][0], events[-1][0]
replay_native = [d for t, _, d in native_seq if t >= replay_floor]
truth_by_proxy_index = {}

print('events', len(events), 'native', len(replay_native), 'epochs', len(epoch_order),
      'anchors', anchor_count, 'anchor_mismatches', raw_anchor_mismatches,
      'ambiguous', len(truth_ambiguous), 'duration_s', (end_ns-start_ns)/1e9)

if args.oracle_response_delay_ms is not None:
  oracle_latency_samples_ms = [args.oracle_response_delay_ms]
elif raw_latency_ms:
  oracle_latency_samples_ms = raw_latency_ms
else:
  oracle_latency_samples_ms = [8.0]
sorted_latency = sorted(oracle_latency_samples_ms)
print('oracle_timing', 'fixed' if args.oracle_response_delay_ms is not None else ('recorded' if raw_latency_ms else 'fallback'),
      'samples', len(oracle_latency_samples_ms),
      'p50_ms', sorted_latency[len(sorted_latency) // 2],
      'p99_ms', sorted_latency[round((len(sorted_latency) - 1) * 0.99)],
      'max_ms', sorted_latency[-1])

if args.scheduler_only:
  scheduler_clock = [0.0]
  scheduler_echoes = deque()
  scheduler_responses = []
  scheduler_expected = deque()
  scheduler_stats = Counter()
  scheduler_failures = []
  scheduler_serial = [0]
  scheduler_request_count = [0]
  scheduler_last_host_at = [None]
  scheduler_max_pending = [0]
  scheduler_max_publication_latency_ms = [0.0]
  scheduler_max_host_gap_ms = [0.0]
  scheduler_state = SimpleNamespace(canValid=True)

  def scheduler_send(msgs):
    nonlocal_scheduler_now = scheduler_clock[0]
    for msg in msgs:
      address, data, bus = int(msg.address), bytes(msg.dat), int(msg.src)
      if address == 0x777 or address == NATIVE_08A_ADDR:
        scheduler_echoes.append((address, data, bus + 0x80))
      if address != NATIVE_08A_ADDR:
        continue
      if not scheduler_expected:
        scheduler_failures.append(('host_without_native_generation', nonlocal_scheduler_now, data.hex()))
        continue
      expected_t, expected_b26, expected_fv4 = scheduler_expected.popleft()
      actual = (data[26] & 0x3F, data[28] >> 4)
      if actual != (expected_b26, expected_fv4):
        scheduler_failures.append(('generation_mismatch', nonlocal_scheduler_now,
                                   (expected_b26, expected_fv4), actual))
      latency_ms = (nonlocal_scheduler_now - expected_t) * 1000.0
      scheduler_max_publication_latency_ms[0] = max(scheduler_max_publication_latency_ms[0], latency_ms)
      if scheduler_last_host_at[0] is not None and nonlocal_scheduler_now - scheduler_last_host_at[0] < 1.0:
        scheduler_max_host_gap_ms[0] = max(scheduler_max_host_gap_ms[0],
                                           (nonlocal_scheduler_now - scheduler_last_host_at[0]) * 1000.0)
      scheduler_last_host_at[0] = nonlocal_scheduler_now
      scheduler_stats['host_publications'] += 1

  scheduler_proxy = ToyotaTss3RequestProxy(scheduler_send, start_thread=False, monotonic=lambda: scheduler_clock[0])
  scheduler_record_failure = scheduler_proxy._record_failure_locked

  def scheduler_count_failure(reason):
    scheduler_stats[f'failure_{reason}'] += 1
    # Every recorded scheduler failure releases authority and invalidates its
    # outstanding signing work. Those generations must not remain publication
    # expectations after the production proxy has deliberately failed open.
    scheduler_expected.clear()
    scheduler_record_failure(reason)

  scheduler_proxy._record_failure_locked = scheduler_count_failure

  def scheduler_drain_echoes():
    while scheduler_echoes:
      address, data, src = scheduler_echoes.popleft()
      scheduler_proxy.update([(0, [(address, data, src)])], scheduler_state)

  def scheduler_run_oracle():
    with scheduler_proxy._cv:
      item = scheduler_proxy._next_job_locked(scheduler_clock[0])
    if item is None:
      return
    seq, job = item
    scheduler_send(build_oracle_transport(seq, job.application, job.message_counter, job.reset_counter))
    scheduler_request_count[0] += 1
    scheduler_stats['oracle_requests'] += 1
    if args.drop_sign_response is not None and scheduler_request_count[0] == args.drop_sign_response:
      scheduler_stats['injected_drops'] += 1
      return
    request_number = scheduler_request_count[0]
    delay_ms = oracle_latency_samples_ms[(request_number - 1) % len(oracle_latency_samples_ms)]
    if args.late_sign_response == request_number:
      delay_ms = max(delay_ms, 75.0)
      scheduler_stats['injected_late_responses'] += 1
    status = 2 if args.error_sign_response == request_number else 0
    if status:
      scheduler_stats['injected_error_responses'] += 1
    scheduler_serial[0] += 1
    heapq.heappush(scheduler_responses, (scheduler_clock[0] + delay_ms / 1000.0,
                                         scheduler_serial[0], seq, job, status))
    if args.duplicate_sign_response == request_number:
      scheduler_serial[0] += 1
      heapq.heappush(scheduler_responses, (scheduler_clock[0] + delay_ms / 1000.0 + 0.001,
                                           scheduler_serial[0], seq, job, status))
      scheduler_stats['injected_duplicate_responses'] += 1

  def scheduler_advance(target_s):
    while scheduler_clock[0] + 0.001 < target_s:
      scheduler_clock[0] += 0.001
      while scheduler_responses and scheduler_responses[0][0] <= scheduler_clock[0] + 1e-12:
        _, _, seq, _job, status = heapq.heappop(scheduler_responses)
        data = bytes((0xC9, seq, status, seq ^ 0xFF, 0x12, 0x34, 0x56, 0x78))
        scheduler_proxy.update([(0, [(ORACLE_RESPONSE_ADDR, data, ORACLE_BUS)])], scheduler_state)
        scheduler_drain_echoes()
      scheduler_run_oracle()
      scheduler_drain_echoes()
      pending = len(scheduler_proxy.jobs) + int(scheduler_proxy.inflight is not None)
      scheduler_max_pending[0] = max(scheduler_max_pending[0], pending)
    scheduler_clock[0] = target_s

  scheduler_events = sorted(
    [(t, order, SECOC_SYNC_ADDR, data, 0) for t, order, data in sync_seq if t >= replay_floor] +
    [(t, order, NATIVE_08A_ADDR, data, UPSTREAM_BUS) for t, order, data in native_seq if t >= replay_floor]
  )
  scheduler_start_ns = scheduler_events[0][0]
  for t, _order, address, data, src in scheduler_events:
    scheduler_advance((t - scheduler_start_ns) / 1e9)
    pending_before = len(scheduler_proxy.jobs) + int(scheduler_proxy.inflight is not None)
    owned_before = scheduler_proxy.active or scheduler_proxy.arm_pending
    scheduler_proxy.update([(t, [(address, data, src)])], scheduler_state)
    pending_after = len(scheduler_proxy.jobs) + int(scheduler_proxy.inflight is not None)
    if address == NATIVE_08A_ADDR and owned_before and pending_after == pending_before + 1:
      scheduler_expected.append((scheduler_clock[0], data[26] & 0x3F, data[28] >> 4))
    if scheduler_proxy.freshness_ready and not scheduler_proxy.control_enabled:
      scheduler_proxy.set_control(True, False, 0.0, long_active=True, accel=0.0, set_speed_kph=0.0)
    if not scheduler_proxy.active and not scheduler_proxy.arm_pending and pending_after == 0:
      scheduler_expected.clear()
    scheduler_drain_echoes()

  scheduler_advance(scheduler_clock[0] + 0.250)
  scheduler_proxy.set_control(False, False, 0.0)
  scheduler_drain_echoes()
  print('SCHEDULER_RESULT', dict(scheduler_stats),
        'max_pending', scheduler_max_pending[0],
        'max_publication_latency_ms', scheduler_max_publication_latency_ms[0],
        'max_continuous_host_gap_ms', scheduler_max_host_gap_ms[0],
        'remaining_expected', len(scheduler_expected),
        'last_failure', scheduler_proxy.last_failure_reason)
  assert scheduler_max_pending[0] <= 8, scheduler_max_pending[0]
  assert not scheduler_failures, scheduler_failures[:20]
  assert not scheduler_expected, len(scheduler_expected)
  fail_open_count = scheduler_stats['failure_oracle_backlog'] + scheduler_stats['failure_oracle_dead']
  if args.expect_fail_open:
    assert fail_open_count > 0, scheduler_stats
  else:
    assert fail_open_count == 0, scheduler_stats
    assert scheduler_max_publication_latency_ms[0] < 100.0, scheduler_max_publication_latency_ms[0]
  for option, stat in ((args.drop_sign_response, 'injected_drops'),
                       (args.duplicate_sign_response, 'injected_duplicate_responses'),
                       (args.error_sign_response, 'injected_error_responses'),
                       (args.late_sign_response, 'injected_late_responses')):
    if option is not None:
      assert scheduler_stats[stat] == 1, (stat, scheduler_stats)
  print('PASS F33 SIGNER SCHEDULER REPLAY')
  raise SystemExit(0)

# Current production safety parameter, not the historical route's rollout bits.
param = EPS_SCALE[CAR.TOYOTA_CAMRY_TSS3] | ToyotaSafetyFlags.F33 | ToyotaSafetyFlags.TSS3_08A_HOST
safety = libsafety_py.libsafety
assert safety.set_safety_hooks(structs.CarParams.SafetyModel.toyota, int(param)) == 0
safety.init_tests()

sim = [0.0]
now_ns = [start_ns]
current_cs = [None]
last_safety_tick_ns = [start_ns]
echo_queue = []
scheduled = []
schedule_serial = 0
stats = Counter()
failures = []
strict_active_native = strict_host_id11 = 0
native_blocked = native_leaked = 0
safety_invalid = False
sign_generation_count = 0
drop_exercised = False


def packet(addr, bus, data):
  p = libsafety_py.make_CANPacket(addr, bus, data)
  if len(data) > 8:
    p[0].fd = 1
  return p


def set_clock(ns):
  now_ns[0] = ns
  sim[0] = (ns - start_ns) / 1e9
  safety.set_timer((ns // 1000) % 0xFFFFFFFF)


def host_tx(msgs):
  global strict_host_id11
  for m in msgs:
    if hasattr(m, 'address'):
      address, data, bus = int(m.address), bytes(m.dat), int(m.src)
    else:
      address, data, bus = int(m[0]), bytes(m[1]), int(m[2])
    ok = bool(safety.safety_tx_hook(packet(address, bus, data)))
    stats[('host_tx', hex(address), 'A' if ok else 'R')] += 1
    if ok and address == 0x777 and data[:3] == bytes((7, 0xC9, 0xA8)):
      stats['arm' if data[3] else 'release'] += 1
    if ok and address == NATIVE_08A_ADDR:
      stats['host_08a_accepted'] += 1
    if not ok:
      if address == NATIVE_08A_ADDR and not safety.get_controls_allowed():
        stats['expected_controls_disallowed_08a_reject'] += 1
      else:
        failures.append(('safety_tx_reject', sim[0], hex(address), safety.get_desired_angle_last(),
                         safety.get_angle_meas_min(), safety.get_angle_meas_max(), data.hex()))
    if address == NATIVE_08A_ADDR and proxy.active and proxy.control_lat_active:
      d = data
      if (d[21] & 0x3F) != 11:
        failures.append(('owned_non_id11_tx', sim[0], d[21] & 0x3F, d.hex()))
      else:
        strict_host_id11 += 1
    echo_queue.append((address, data, bus + (0x80 if ok else 0xC0)))


def drain_echo():
  while echo_queue and current_cs[0] is not None:
    a, d, s = echo_queue.pop(0)
    proxy.update([(now_ns[0], [(a, d, s)])], current_cs[0])


def oracle_cmac(job):
  truth = truth_by_proxy_index.get(job.native_index)
  if truth is None:
    failures.append(('oracle_truth_unknown', sim[0], job.native_index))
  elif job.message_counter != truth:
    failures.append(('wrong_sign_message_counter', sim[0], job.native_index, job.message_counter, truth))
  return bytes.fromhex('12345678')


with structs.CarParams.from_bytes(cp_bytes) as recorded_cp:
  cp = recorded_cp.as_builder()
  cp.safetyConfigs[0].safetyParam = int(param)
  cp.openpilotLongitudinalControl = True
  cp.alphaLongitudinalAvailable = True
  ci = CarInterface(cp)
  proxy = ToyotaTss3RequestProxy(host_tx, start_thread=False, monotonic=lambda: sim[0])

  def schedule(when, kind, seq, job):
    global schedule_serial
    schedule_serial += 1
    heapq.heappush(scheduled, (when, schedule_serial, kind, seq, job))

  def deliver_due():
    while scheduled and scheduled[0][0] <= sim[0] + 1e-12:
      _, _, kind, seq, job = heapq.heappop(scheduled)
      if current_cs[0] is None or kind != 'response':
        continue
      data = bytes((0xC9, seq, 0, seq ^ 0xFF)) + oracle_cmac(job)
      proxy.update([(now_ns[0], [(ORACLE_RESPONSE_ADDR, data, ORACLE_BUS)])], current_cs[0])
      drain_echo()

  def run_oracle_step():
    global sign_generation_count, drop_exercised
    with proxy._cv:
      item = proxy._next_job_locked(sim[0])
    if item is None:
      return
    seq, job = item
    frames = build_oracle_transport(seq, job.application, job.message_counter, job.reset_counter)
    host_tx(frames)
    drain_echo()
    stats['oracle_request_batches'] += 1
    sign_generation_count += 1
    if args.drop_sign_response is not None and sign_generation_count == args.drop_sign_response:
      drop_exercised = True
      stats['injected_sign_drop'] += 1
    else:
      delay_ms = oracle_latency_samples_ms[(sign_generation_count - 1) % len(oracle_latency_samples_ms)]
      schedule(sim[0] + delay_ms / 1000.0, 'response', seq, job)

  def advance_to(target_ns):
    while now_ns[0] + 1_000_000 < target_ns:
      set_clock(now_ns[0] + 1_000_000)
      deliver_due()
      run_oracle_step()
      deliver_due()
      drain_echo()
    set_clock(target_ns)
    deliver_due()
    run_oracle_step()
    deliver_due()
    drain_echo()

  was_lat_active = False
  was_enabled = False
  active_windows = 0
  enabled_windows = 0
  for _idx, (t, _prio, _ord, kind, payload) in enumerate(events):
    advance_to(t)
    if kind == 'can':
      for a, d, s in payload:
        fwd = safety.safety_fwd_hook(s, a)
        if a == NATIVE_08A_ADDR and s == 2 and proxy.active:
          strict_active_native += 1
          if fwd == -1:
            native_blocked += 1
          else:
            native_leaked += 1
            failures.append(('native_leak', sim[0], fwd, d[26] & 0x3F))
        if not safety.safety_rx_hook(packet(a, s, d)):
          stats[('rx_invalid', hex(a), s)] += 1
      current_cs[0] = ci.update([(t, payload)])
      for a, d, s in payload:
        before_index = proxy.native_index
        proxy.update([(t, [(a, d, s)])], current_cs[0])
        if a == NATIVE_08A_ADDR and s == 2 and proxy.native_index == before_index + 1:
          truth_by_proxy_index[proxy.native_index] = truth_by_frame.get(d)
          if proxy.freshness_ready:
            expected_counter = truth_by_proxy_index[proxy.native_index]
            if expected_counter is not None and proxy.tracker.message_counter != expected_counter:
              failures.append(('tracker_truth_mismatch', sim[0], proxy.native_index,
                               proxy.tracker.message_counter, expected_counter))
            stats['freshness_ready_native_updates'] += 1
      drain_echo()
      if now_ns[0] - last_safety_tick_ns[0] >= 1_000_000_000:
        safety.safety_tick()
        safety_invalid |= not safety.safety_config_valid()
        last_safety_tick_ns[0] = now_ns[0]
    else:
      with structs.CarControl.from_bytes(payload) as CC:
        if bool(CC.enabled) and not was_enabled and current_cs[0] is not None:
          ci.CC.reset_tss3_lateral_target(current_cs[0].steeringAngleDeg + current_cs[0].steeringAngleOffsetDeg)
        out, can_sends = ci.apply(CC, t)
        if can_sends:
          host_tx(can_sends)
          drain_echo()
        proxy.set_control(CC.enabled, CC.latActive, out.steeringAngleDeg,
                          long_active=cp.openpilotLongitudinalControl and CC.longActive,
                          accel=out.accel,
                          set_speed_kph=current_cs[0].vCruise if current_cs[0] is not None else 0.0)
        drain_echo()
        if bool(CC.latActive) and not was_lat_active:
          active_windows += 1
        if bool(CC.enabled) and not was_enabled:
          enabled_windows += 1
        was_lat_active = bool(CC.latActive)
        was_enabled = bool(CC.enabled)

  advance_to(end_ns + 200_000_000)
  if proxy.active or proxy.arm_pending:
    proxy.set_control(False, False, 0.0)
    drain_echo()

  print('RESULT active', proxy.active, 'freshness_ready', proxy.freshness_ready,
        'arms', stats['arm'], 'releases', stats['release'],
        'host_08a_accepted', stats['host_08a_accepted'], 'last_failure', proxy.last_failure_reason)
  print('enabled_windows', enabled_windows, 'active_windows', active_windows,
        'active_native', strict_active_native, 'host_id11', strict_host_id11,
        'blocked', native_blocked, 'leaked', native_leaked, 'safety_invalid', safety_invalid)
  print('stats', stats)
  for f in failures[:100]:
    print('FAIL', f)

  if args.drop_sign_response is not None:
    assert drop_exercised, f'did not reach sign generation {args.drop_sign_response}'
  assert proxy.last_failure_reason == '', proxy.last_failure_reason
  assert stats['arm'] == stats['release'] == enabled_windows, (stats['arm'], stats['release'], enabled_windows)
  assert stats['arm'] > 0
  assert strict_host_id11 > 100
  assert native_leaked == 0
  assert not safety_invalid
  assert not failures, failures[:20]
  unexpected_rejects = sum(v for k, v in stats.items() if isinstance(k, tuple) and len(k) >= 3 and k[0] == 'host_tx' and k[2] == 'R')
  unexpected_rejects -= stats['expected_controls_disallowed_08a_reject']
  assert unexpected_rejects == 0, unexpected_rejects
  print('PASS F33 FULL ROUTE REPLAY')
