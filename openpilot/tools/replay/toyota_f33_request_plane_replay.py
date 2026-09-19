from __future__ import annotations
import argparse
from pathlib import Path
from bisect import bisect_right
from collections import Counter, defaultdict
import heapq

from openpilot.tools.lib.logreader import LogReader
from opendbc.car import structs
from opendbc.car.toyota.interface import CarInterface
from opendbc.safety.tests.libsafety import libsafety_py
from openpilot.selfdrive.car.toyota_tss3_08a import decode_sync
from openpilot.selfdrive.car.toyota_tss3_08a_signed import (
  ToyotaTss3RequestProxy,
  build_oracle_transport,
  resolve_epoch,
  mac28_hex_from_native,
  NATIVE_08A_ADDR,
  ORACLE_RESPONSE_ADDR,
  ORACLE_BUS,
)

parser = argparse.ArgumentParser(description="Replay a local F33 route through current CarController, request proxy, and Panda safety")
parser.add_argument("route", type=Path, help="local route directory containing segment subdirectories with rlog.zst")
parser.add_argument("--drop-sign-response", type=int, metavar="N", help="drop the Nth first-attempt sign response to exercise retry behavior")
parser.add_argument("--drop-sign-attempts", type=int, default=1, choices=(1, 2), help="drop primary reply only (1) or primary+CF-repair reply (2)")
parser.add_argument("--drop-verify-response", action="store_true", help="drop the first qualification verify response")
parser.add_argument("--oracle-response-delay-ms", type=float, default=20.0, help="synthetic successful oracle response latency (default: 20 ms)")
args = parser.parse_args()
ROOT = args.route
files = sorted(ROOT.glob('*/rlog.zst'), key=lambda p: int(p.parent.name.rsplit('--', 1)[1]))
if not files:
  raise RuntimeError(f"no rlog.zst segments found under {ROOT}")

# Plain event extraction; ignore old host echoes/sendcan. Re-run current stack from native inputs + recorded CarControl.
events = []
cp_bytes = None
sync_seq = []
native_seq = []
recorded_oracle_tx = []
recorded_oracle_rx = []
order = 0
for f in files:
  for m in LogReader(str(f), sort_by_time=False):
    t = int(m.logMonoTime)
    w = m.which()
    if w == 'carParams' and cp_bytes is None:
      cp_bytes = m.carParams.as_builder().to_bytes()
    elif w == 'can':
      for x in m.can:
        if int(x.address) == ORACLE_RESPONSE_ADDR and int(x.src) == ORACLE_BUS and len(x.dat) == 8 and bytes(x.dat)[:2] == b'\x07\xc9':
          recorded_oracle_rx.append((t, bytes(x.dat)))
      frames = [(int(x.address), bytes(x.dat), int(x.src)) for x in m.can if int(x.src) < 128 and int(x.address) != ORACLE_RESPONSE_ADDR]
      if frames:
        events.append((t, 0, order, 'can', frames))
        order += 1
        for a, d, s in frames:
          if a == 0x00F and s == 0 and len(d) == 8:
            sync_seq.append((t, order, d))
          if a == NATIVE_08A_ADDR and s == 2 and len(d) == 32:
            native_seq.append((t, order, d))
    elif w == 'sendcan':
      for x in m.sendcan:
        if int(x.address) == 0x7A1 and int(x.src) == ORACLE_BUS and len(x.dat) == 8:
          recorded_oracle_tx.append((t, bytes(x.dat)))
    elif w == 'carControl':
      events.append((t, 1, order, 'cc', m.carControl.as_builder().to_bytes()))
      order += 1
if cp_bytes is None:
  raise RuntimeError('missing CarParams')
events.sort()
start_ns = events[0][0]
end_ns = events[-1][0]

# Independent native truth reconstructed per resolved reset epoch. Log batches can
# contain source frames out of order, so do not propagate by recorder arrival order.
sync_seq.sort()
native_seq.sort()
sts = [x[0] for x in sync_seq]
truth_by_frame = {}
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

# Within one reset epoch, full message counter starts at 1 and increments with
# B26. Find the source-phase frame (low2=1) whose cyclic B26 distances make the
# entire epoch self-consistent. This is independent of recorder ordering.
truth_ambiguous = []
for ep in epoch_order:
  rows = epoch_groups[ep]
  candidates = []
  for _, _, start_frame in rows:
    if ((start_frame[28] >> 6) & 3) != 1:
      continue
    sb = start_frame[26] & 0x3F
    ds = []
    seen = set()
    ok = True
    for _, _, d in rows:
      dist = ((d[26] & 0x3F) - sb) & 0x3F
      if dist in seen or dist > 31 or (((dist + 1) & 3) != ((d[28] >> 6) & 3)):
        ok = False
        break
      seen.add(dist)
      ds.append(dist)
    if ok:
      candidates.append((max(ds), sb))
  if not candidates:
    truth_ambiguous.append((ep, 'none', len(rows)))
    continue
  candidates.sort()
  best_max, best_b26 = candidates[0]
  # A second equally short phase would make the offline oracle ambiguous.
  if len(candidates) > 1 and candidates[1][0] == best_max:
    truth_ambiguous.append((ep, 'tie', candidates[:3]))
    continue
  for _, _, d in rows:
    dist = ((d[26] & 0x3F) - best_b26) & 0x3F
    truth_by_frame[d] = dist + 1

# The first route epoch may be partial. Never let it qualify the mock oracle.
if epoch_order:
  for _, _, d in epoch_groups[epoch_order[0]]:
    truth_by_frame.pop(d, None)

# Cross-check the independent truth model against hardware-recorded EPS oracle
# recovery/verify responses retained in the route. Modified sign domains do not
# match a native application and are intentionally excluded from this anchor set.
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
  ep = epoch_by_frame.get(d)
  if ep is not None:
    native_by_application[d[:28]].append((d, ep, mac28_hex_from_native(d)))

anchor_count = 0
anchor_mismatches = []
for t, seq, domain in recorded_requests:
  response = next((frame for rt, frame in responses_by_seq[seq] if rt >= t and rt - t < 500_000_000), None)
  if response is None:
    continue
  packed = int.from_bytes(domain[32:36], 'big')
  epoch = (int.from_bytes(domain[30:32], 'big'), (packed >> 12) & 0xFFFFF)
  candidate_message = (packed >> 4) & 0xFF
  cmac28 = response[4:8].hex()[:7]
  for native_frame, native_epoch, native_mac28 in native_by_application.get(domain[2:30], []):
    if native_epoch == epoch and native_mac28 == cmac28:
      truth = truth_by_frame.get(native_frame)
      if truth is not None:
        anchor_count += 1
        if truth != candidate_message:
          anchor_mismatches.append((epoch, candidate_message, truth, native_frame[26] & 0x3F))
      break
if anchor_count == 0:
  raise RuntimeError('route contains no independently matched EPS-oracle freshness anchors')
if anchor_mismatches:
  raise AssertionError(f'EPS-oracle anchor mismatch: {anchor_mismatches[:10]}')

# Skip only the leading partial epoch. Start from the last 0x00F before the
# second resolved epoch so the production proxy has sync context but fewer than
# eight unknown native frames before independently-known truth begins.
if len(epoch_order) > 1:
  truth_boundary = min(t for t, _, _ in epoch_groups[epoch_order[1]])
  pre_sync = [t for t, _, _ in sync_seq if t <= truth_boundary]
  replay_floor = max(pre_sync) if pre_sync else truth_boundary
  events = [e for e in events if e[0] >= replay_floor]
start_ns = events[0][0]
end_ns = events[-1][0]
print(
  'events',
  len(events),
  'native',
  len(native_seq),
  'truth',
  len(truth_by_frame),
  'epochs',
  len(epoch_order),
  'ambiguous',
  len(truth_ambiguous),
  'anchors',
  anchor_count,
  'duration_s',
  (end_ns - start_ns) / 1e9,
)
print('truth_ambiguous', truth_ambiguous[:10])

safety = libsafety_py.libsafety
assert safety.set_safety_hooks(structs.CarParams.SafetyModel.toyota, 53833) == 0
safety.init_tests()

sim = [0.0]
now_ns = [start_ns]
current_cs = [None]
echo_queue = []
responses = []
response_serial = 0
stats = Counter()
failures = []
strict_active_native = 0
strict_host_id11 = 0
first_drop_done = False
sign_generation_count = 0
dropped_native_index = None
dropped_attempts = 0
drop_retry_exercised = False
verify_drop_done = False


# Helper to package CAN for C safety.
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
    p = packet(int(m.address), int(m.src), bytes(m.dat))
    ok = bool(safety.safety_tx_hook(p))
    stats[('host_tx', hex(int(m.address)), 'A' if ok else 'R')] += 1
    if not ok:
      failures.append(('safety_tx_reject', sim[0], hex(int(m.address)), int(m.src), bytes(m.dat).hex()))
    if int(m.address) == NATIVE_08A_ADDR and proxy.active and proxy.control_lat_active:
      ident = bytes(m.dat)[21] & 0x3F
      if ident != 11:
        failures.append(('owned_non_id11_tx', sim[0], ident, bytes(m.dat).hex()))
      elif bytes(m.dat)[24] != 100:
        failures.append(('owned_id11_wrong_assist_gain', sim[0], bytes(m.dat)[24], bytes(m.dat).hex()))
      else:
        strict_host_id11 += 1
    echo_queue.append((int(m.address), bytes(m.dat), int(m.src) + (0x80 if ok else 0xC0)))


def drain_echo():
  while echo_queue and current_cs[0] is not None:
    a, d, s = echo_queue.pop(0)
    proxy.update([(now_ns[0], [(a, d, s)])], current_cs[0])


# Oracle response payload independently validates candidate/full message against source-native truth.
def oracle_cmac(job):
  if job.native_index is None:
    return bytes.fromhex('00000000')
  ev = proxy._event_by_index_locked(int(job.native_index))
  if ev is None:
    failures.append(('oracle_missing_native_event', sim[0], job.kind, job.native_index))
    return bytes.fromhex('00000000')
  true = truth_by_frame.get(ev.frame)
  if true is None:
    failures.append(('oracle_truth_unknown', sim[0], job.kind, job.native_index))
    return bytes.fromhex('00000000')
  if job.kind in ('recover', 'verify'):
    good = job.candidate_message == true
    if good:
      return bytes.fromhex((job.expected_mac28 or '0000000') + '0')
    wrong = '00000000'
    if (job.expected_mac28 or '') == '0000000':
      wrong = 'ffffffff'
    return bytes.fromhex(wrong)
  if job.kind == 'sign':
    if job.message_counter != true:
      failures.append(('wrong_sign_message_counter', sim[0], job.native_index, job.message_counter, true, ev.b26, hex(ev.reset_counter)))
    ep = epoch_by_frame.get(ev.frame)
    if ep != (job.trip_counter, job.reset_counter):
      failures.append(('wrong_sign_epoch', sim[0], job.native_index, (job.trip_counter, job.reset_counter), ep))
    return bytes.fromhex('12345678')
  return bytes.fromhex('00000000')


# Instantiate current production CI and proxy while CP reader stays alive.
with structs.CarParams.from_bytes(cp_bytes) as cp:
  print('CP', cp.carFingerprint, cp.passive, [(str(x.safetyModel), int(x.safetyParam)) for x in cp.safetyConfigs])
  ci = CarInterface(cp)
  proxy = ToyotaTss3RequestProxy(host_tx, start_thread=False, monotonic=lambda: sim[0], sleep=lambda _: None)

  def deliver_due_responses():
    while responses and responses[0][0] <= sim[0] + 1e-12:
      _, _, seq, data = heapq.heappop(responses)
      if current_cs[0] is not None:
        proxy.update([(now_ns[0], [(ORACLE_RESPONSE_ADDR, data, ORACLE_BUS)])], current_cs[0])
        drain_echo()

  def run_oracle_step():
    global response_serial, first_drop_done, sign_generation_count, dropped_native_index, dropped_attempts
    global drop_retry_exercised, verify_drop_done
    with proxy._cv:
      repair = proxy._next_cf_repair_locked(sim[0])
    if repair is not None:
      seq, job = repair
      _, cfs = build_oracle_transport(seq, job.domain)
      host_tx(cfs)
      drain_echo()
      stats[('oracle_cf_repair', job.kind)] += 1
      if job.kind == 'sign' and dropped_native_index == job.native_index:
        drop_retry_exercised = True
        stats['injected_sign_cf_repair'] += 1
        if args.drop_sign_attempts >= 2:
          stats['injected_sign_repair_drop'] += 1
          return
        cmac = oracle_cmac(job)
        data = bytes((0x07, 0xC9, seq, 0)) + cmac
        response_serial += 1
        heapq.heappush(responses, (sim[0] + 0.010, response_serial, seq, data))
      return

    with proxy._cv:
      item = proxy._next_job_locked(sim[0])
    if item is None:
      return
    seq, job = item
    ff, cfs = build_oracle_transport(seq, job.domain)
    host_tx([ff])
    host_tx(cfs)
    drain_echo()
    stats[('oracle_job', job.kind)] += 1
    if job.kind == 'verify' and args.drop_verify_response and not verify_drop_done:
      verify_drop_done = True
      stats['injected_verify_drop'] += 1
      return
    if job.kind == 'sign':
      if getattr(job, 'retry_count', 0) == 0:
        sign_generation_count += 1
        if args.drop_sign_response is not None and sign_generation_count == args.drop_sign_response:
          first_drop_done = True
          dropped_native_index = job.native_index
      if dropped_native_index is not None and job.native_index == dropped_native_index and dropped_attempts == 0:
        dropped_attempts = 1
        stats['injected_sign_drop'] += 1
        # Model the road failure class: EPS flow-control arrives, but the private
        # reply does not. Production then repairs this same FF/session with one
        # bounded repeat of CF1..CF5 rather than opening a new transaction.
        fc = bytes.fromhex("3000280000000000")
        response_serial += 1
        heapq.heappush(responses, (sim[0] + 0.017, response_serial, seq, fc))
        return
    cmac = oracle_cmac(job)
    data = bytes((0x07, 0xC9, seq, 0)) + cmac
    response_serial += 1
    heapq.heappush(responses, (sim[0] + args.oracle_response_delay_ms / 1000.0, response_serial, seq, data))

  # advance simulation in 1ms scheduler ticks only when needed; route event cadence remains source-real.
  def advance_to(target_ns):
    if target_ns < now_ns[0]:
      return
    while now_ns[0] + 1_000_000 < target_ns:
      set_clock(now_ns[0] + 1_000_000)
      deliver_due_responses()
      run_oracle_step()
      deliver_due_responses()
      drain_echo()
    set_clock(target_ns)
    deliver_due_responses()
    run_oracle_step()
    deliver_due_responses()
    drain_echo()

  was_active = False
  active_windows = 0
  native_blocked = 0
  native_leaked = 0
  safety_invalid = False
  for idx, (t, _prio, _ord, kind, payload) in enumerate(events):
    advance_to(t)
    if kind == 'can':
      # Board order: forwarding hook runs before RX hook.
      for a, d, s in payload:
        fwd = safety.safety_fwd_hook(s, a)
        if a == NATIVE_08A_ADDR and s == 2:
          if proxy.active and proxy.control_lat_active:
            strict_active_native += 1
            if fwd == -1:
              native_blocked += 1
            else:
              native_leaked += 1
              failures.append(('native_08a_forwarded_while_owned', sim[0], fwd, d[21] & 0x3F, d[26] & 0x3F))
        ok = bool(safety.safety_rx_hook(packet(a, s, d)))
        if not ok:
          stats[('rx_invalid', hex(a), s)] += 1
      # Feed production CI/proxy only native bus packets, never old route host echoes.
      current_cs[0] = ci.update([(t, payload)])
      proxy.update([(t, payload)], current_cs[0])
      drain_echo()
      # Keep safety RX validity honest after warmup.
      if sim[0] > 2.0:
        safety.safety_tick_current_safety_config()
        if not safety.safety_config_valid():
          safety_invalid = True
    else:
      with structs.CarControl.from_bytes(payload) as CC:
        if hasattr(ci.CC, 'tss3_request_plane_active'):
          ci.CC.tss3_request_plane_active = proxy.active
        out, can_sends = ci.apply(CC, t)
        if can_sends:
          host_tx(can_sends)
          drain_echo()
        proxy.set_control(CC.latActive, out.steeringAngleDeg)
        drain_echo()
        if bool(CC.latActive) and not was_active:
          active_windows += 1
        was_active = bool(CC.latActive)
    if idx % 10000 == 0 and idx:
      print(
        'progress',
        idx,
        '/',
        len(events),
        't',
        round(sim[0], 1),
        'active',
        proxy.active,
        'qualified',
        proxy.qualified,
        'mods',
        proxy.modified_tx_count,
        'releases',
        proxy.release_count,
        'fail',
        len(failures),
      )

  advance_to(end_ns + 500_000_000)
  print('RESULT')
  print(
    'proxy active',
    proxy.active,
    'qualified',
    proxy.qualified,
    'arms',
    proxy.arm_count,
    'releases',
    proxy.release_count,
    'modified',
    proxy.modified_tx_count,
    'transparent',
    proxy.transparent_tx_count,
    'timeouts',
    proxy.oracle_timeout_count,
    'recovery',
    proxy.recovery_count,
    'verify',
    proxy.verification_count,
  )
  print(
    'active_windows',
    active_windows,
    'active_native',
    strict_active_native,
    'host_id11',
    strict_host_id11,
    'blocked',
    native_blocked,
    'leaked',
    native_leaked,
    'safety_invalid',
    safety_invalid,
    'drop',
    first_drop_done,
  )
  print('stats')
  for k, v in stats.most_common():
    print(k, v)
  print('failures', len(failures))
  for f in failures[:100]:
    print('FAIL', f)
  # Strict gate: route must exercise ownership; every owned native is blocked, no Panda rejects, no wrong freshness.
  if args.drop_sign_response is not None:
    assert first_drop_done, f'did not reach sign generation {args.drop_sign_response}'
    assert drop_retry_exercised, f'dropped sign generation {args.drop_sign_response} did not exercise same-session CF repair'
  if args.drop_verify_response:
    assert verify_drop_done, 'verify response injection was not exercised'
  assert proxy.arm_count > 0, 'never armed'
  assert proxy.arm_count == proxy.release_count == active_windows, (proxy.arm_count, proxy.release_count, active_windows)
  assert strict_host_id11 > 100, f'not enough sustained host ID11: {strict_host_id11}'
  assert native_leaked == 0, f'native leaks while owned: {native_leaked}'
  assert not safety_invalid, 'safety RX config invalid'
  assert not failures, failures[:20]
  assert not any(k[0] == 'host_tx' and k[2] == 'R' for k in stats if isinstance(k, tuple) and len(k) >= 3), 'host tx rejects present'
  print('PASS F33 FULL ROUTE REPLAY')
