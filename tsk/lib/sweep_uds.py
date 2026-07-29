#!/usr/bin/env python3
"""Exhaustive UDS boundary sweep — every service byte, every sub-function, no skip list.

The Corolla EPS (8965F1208000, bus 1) answers every read service and goes completely
silent on the reprogramming set (0x10 sub-function 02, 0x28, 0x34, 0x85). Silence is not
a refusal — this EPS says "no" freely and precisely elsewhere — so the silent set is
either a filter on the path or firmware that doesn't implement those services. Mapping
exactly where the boundary falls is what separates those, and a curated list of
"meaningful" services can't do it: ISO 14229 reserves ranges for manufacturer-specific
services, and a Toyota-proprietary service is precisely where a way past a reflash block
would live.

So: every service 0x00-0xFF, every sub-function 0x00-0xFF, in both sessions, with no
service omitted for being dangerous, undocumented, or uninteresting.

**Safety is a constraint on how a value is sent, never on whether it is sent.**
  - The service-existence layer sends the BARE service byte. A service that takes a
    sub-function sees a malformed request and answers NRC 0x13 without acting; a bare
    byte cannot name a valid sub-function, so it is the least-active possible probe.
  - DEFAULT session is swept before EXTENDED. Nearly everything destructive is session
    gated, so the first pass is the safest one.
  - The sub-function layer CAN name real operations (0x11 01 resets the ECU, 0x28 03
    disables comms). It runs anyway — that is the point of the sweep — but stateful
    families run last, and every stateful request is followed by restoration (DEFAULT
    session, 0x28 enable rx/tx, 0x85 DTC on), liveness, and route rediscovery if needed.

**Coverage is bounded by a deadline, never by a skip list.** Each run takes
`budget_seconds` (5 minutes in Not Ready to Drive, before the 12V sags) and stops
cleanly at the frontier. Every result is appended to `uds_sweep.ndjson` as it arrives,
so a mid-run power loss costs nothing, and the next run reads the file, skips what is
already answered, and continues. Two or three short sessions compose into one full map.

Four outcomes, all informative:
  positive  — supported and reachable
  nrc 0x11  — the ECU says it does not have that service. A real answer.
  nrc other — the service EXISTS and we asked wrong (0x13/0x22/0x31/0x7e/0x7f). The most
              interesting bucket, and where an undocumented service shows up.
  silent    — the wall

The response timeout is measured, not guessed: a known-good request is timed at startup
and the silence threshold is set to a multiple of the observed round trip. A slow service
still emits NRC 0x78 (response pending) quickly, which extends the wait, so a short
window rarely manufactures a false silence — and the last stage re-probes everything
classified silent at 10x the timeout anyway.

is_agnos-gated; the server mocks it off-device.
"""
import json
import os
import time
from datetime import datetime, UTC
from uuid import uuid4

from tsk.lib.env import CACHE_DIR, is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.dump_dataflash import ADDR
from tsk.lib.dump_diag import CANDIDATE_BUSES
from tsk.lib.diagnostic_route import discover_eps_route, probe_response_route

SWEEP_DIR = f"{CACHE_DIR}/tsk/uds-sweep"
SWEEP_PATH = f"{SWEEP_DIR}/uds_sweep.ndjson"

DEFAULT_BUDGET = 300.0        # 5 minutes — the Not Ready to Drive 12V window
CALIBRATION_SAMPLES = 5
MIN_TIMEOUT = 0.05
MAX_TIMEOUT = 0.30
TIMEOUT_MULTIPLE = 10         # silence threshold = this x the observed round trip
PENDING_EXTRA = 1.0           # extra wait granted when the ECU says response-pending
LONG_TIMEOUT_MULTIPLE = 10    # the re-probe pass multiplies the calibrated timeout by this

SERVICE_RANGE = range(0x100)
SUBFUNCTION_RANGE = range(0x100)
ADDRESS_RANGE = range(0x700, 0x800)

# DID blocks worth a scoped pass. The full 16-bit space is 65536 requests (~16 min) and
# does not fit the window; these three cover identity, the block Willem's payload upload
# writes, and the manufacturer-specific range.
DID_BLOCKS = [(0xF100, 0xF1FF, "identity"), (0x0200, 0x02FF, "willem"),
              (0xFD00, 0xFEFF, "manufacturer")]

# Prior Corolla work found these requests silent. They remain visible as hypotheses in
# results and documentation, but they do not seed or filter a Camry sweep. Cross-ECU
# comparisons are built from requests actually observed in the current transcript.
PRIOR_REFLASH_HYPOTHESES = [
  {"request": "1002", "label": "programming session"},
  {"request": "28", "label": "communication control"},
  {"request": "34", "label": "request download"},
  {"request": "85", "label": "control DTC setting"},
]

CALIBRATION_REQUEST = b"\x22\xf1\x81"
TESTER_PRESENT_REQUEST = b"\x3e\x00"
RESTORE_REQUESTS = (b"\x10\x01", b"\x28\x00\x01", b"\x85\x01", b"\x10\x01")
KEEPALIVE_INTERVAL = 1.5

# Coverage remains exhaustive. These sets only control scheduling: observation-first
# services run before state-changing families, whose subfunctions receive a liveness
# boundary and restoration immediately after each request.
OBSERVATION_FIRST = (0x22, 0x19, 0x3E, 0x23, 0x27, 0x10)
STATEFUL_SERVICES = {0x11, 0x14, 0x28, 0x2E, 0x31, 0x34, 0x36, 0x37, 0x85, 0xAB, 0xBA}


def ordered_services(service_ids) -> list[int]:
  values = set(service_ids)
  first = [sid for sid in OBSERVATION_FIRST if sid in values]
  middle = sorted(values - set(first) - STATEFUL_SERVICES)
  last = sorted(values & STATEFUL_SERVICES)
  return first + middle + last


def ordered_subfunction_services(service_ids) -> list[int]:
  ordered = ordered_services(service_ids)
  passive = [sid for sid in ordered if sid != 0x10 and sid not in STATEFUL_SERVICES]
  active = [sid for sid in ordered if sid == 0x10 or sid in STATEFUL_SERVICES]
  return passive + active


def needs_liveness_boundary(stateful: bool, sent: int) -> bool:
  return stateful or (sent > 0 and sent % 16 == 0)


def ordered_subfunctions(sid: int) -> list[int]:
  values = list(SUBFUNCTION_RANGE)
  if sid == 0x10:
    # Establish known default/extended/safety sessions before PROGRAMMING; the rest
    # still run, and PROGRAMMING remains in the exhaustive set.
    prefix = [0x01, 0x03, 0x04]
    return prefix + [value for value in values if value not in (*prefix, 0x02)] + [0x02]
  return values


def _noop(**kwargs) -> None:
  pass


def parse_isotp_frame(data: bytes):
  """First-frame parse only — service + NRC live in the first frame either way, and
  skipping reassembly keeps the sweep fast enough to finish inside the window."""
  if not data:
    return None
  pci = data[0] >> 4
  if pci == 0x0:
    n = data[0] & 0x0F
    body = bytes(data[1:1 + n])
  elif pci == 0x1:
    body = bytes(data[2:])
  else:
    return None
  if not body:
    return None
  if body[0] == 0x7F:
    sid = body[1] if len(body) > 1 else -1
    nrc = body[2] if len(body) > 2 else -1
    return {"outcome": "nrc", "sid": sid, "nrc": nrc, "raw": body.hex()}
  return {"outcome": "positive", "sid": body[0], "nrc": -1, "raw": body.hex()}


def ask(panda, bus: int, tx: int, rx: int, payload: bytes, timeout: float,
        response_bus: int | None = None) -> dict:
  """Send a raw request and classify the first response frame. Never raises."""
  try:
    panda.can_recv()   # drain, so a stale frame is not attributed to this request
  except Exception:
    pass

  from opendbc.car.isotp import isotp_send
  t0 = time.monotonic()
  try:
    isotp_send(panda, payload, tx, bus=bus)
  except Exception as e:
    return {"outcome": "send_error", "sid": -1, "nrc": -1, "raw": "",
            "detail": type(e).__name__, "ms": 0}

  expected_bus = bus if response_bus is None else response_bus
  deadline = t0 + timeout
  while time.monotonic() < deadline:
    try:
      frames = panda.can_recv()
    except Exception:
      break
    for addr, *_rest, data, rbus in frames:
      if rbus >= 0x80 or rbus != expected_bus or addr != rx:
        continue   # rbus >= 0x80 is the panda's echo of our own transmit
      parsed = parse_isotp_frame(bytes(data))
      if parsed is None:
        continue
      if parsed["outcome"] == "nrc" and parsed["nrc"] == 0x78:
        deadline = time.monotonic() + PENDING_EXTRA   # response pending: grant more time
        continue
      parsed["ms"] = int((time.monotonic() - t0) * 1000)
      return parsed
  return {"outcome": "silent", "sid": -1, "nrc": -1, "raw": "",
          "ms": int((time.monotonic() - t0) * 1000)}


class Recorder:
  """Append every result with run identity, timing, and resumable request keys."""

  def __init__(self, path: str = SWEEP_PATH):
    self.path = path
    self.run_id = f"nrtd-sweep-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
    self.run_started_ns = time.monotonic_ns()
    self.done: set[str] = set()
    self.count = 0
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
      with open(path, encoding="utf-8") as f:
        for line in f:
          try:
            rec = json.loads(line)
          except Exception:
            continue
          key = rec.get("key")
          if key:
            self.done.add(str(key))
          self.count += 1
    except FileNotFoundError:
      pass
    self.fh = open(path, "a", encoding="utf-8")
    self.write_event("run_start", operation="nrtd_uds_sweep",
                     time_utc=datetime.now(UTC).isoformat())

  def seen(self, key: str) -> bool:
    return key in self.done

  def _append(self, rec: dict) -> None:
    rec.setdefault("run_id", self.run_id)
    rec.setdefault("t_mono_ns", time.monotonic_ns())
    rec.setdefault("t_rel_ms", round((time.monotonic_ns() - self.run_started_ns) / 1_000_000, 3))
    self.fh.write(json.dumps(rec, sort_keys=True) + "\n")
    self.fh.flush()
    self.count += 1

  def write(self, key: str, **fields) -> None:
    rec = {"event": "uds_result", "key": key}
    rec.update(fields)
    self._append(rec)
    self.done.add(key)

  def write_event(self, event: str, **fields) -> None:
    rec = {"event": event}
    rec.update(fields)
    self._append(rec)

  def close(self) -> None:
    try:
      self.write_event("run_end", operation="nrtd_uds_sweep")
      os.fsync(self.fh.fileno())
      self.fh.close()
    except Exception:
      pass


def sweep(progress_cb=None, budget_seconds: float = DEFAULT_BUDGET, mode: str = "nrtd") -> dict:
  """Run the sweep until the budget runs out. Returns:
    {status, panda, eps_bus, timeout_ms, stages[], answering[], silent[], responders[],
     records, frontier, message}
  status is "complete" (nothing left to ask) | "partial" (budget hit, resume to continue)
  | "unreachable" | "failed". Raises NotAGNOSError off-device.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop
  started = time.monotonic()

  def remaining() -> float:
    return budget_seconds - (time.monotonic() - started)

  stages: list = []
  answering: list = []
  silent: list = []
  responders: list = []
  result = {
    "status": "failed", "panda": "", "eps_bus": -1, "timeout_ms": 0, "stages": stages,
    "answering": answering, "silent": silent, "responders": responders, "records": 0,
    "frontier": "", "mode": mode, "hypotheses": PRIOR_REFLASH_HYPOTHESES,
    "message": "",
  }

  from opendbc.car.structs import CarParams

  import subprocess
  subprocess.run(["pkill", "-9", "-f", "manager.py"], check=False)
  subprocess.run(["pkill", "-9", "-f", "pandad"], check=False)
  time.sleep(2)

  try:
    panda = TSKExtractor._connect_panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    try:
      ver = panda.get_version()
      result["panda"] = ver.decode(errors="replace") if isinstance(ver, (bytes, bytearray)) else str(ver)
    except Exception:
      result["panda"] = "unknown"
  except Exception as e:
    result["message"] = f"Connect failed: {type(e).__name__}: {e}"
    return result

  rec = Recorder()

  def rx_of(tx: int) -> int:
    return tx + 8

  try:
    # --- test the prior Toyota route without assuming its response ID/bus ----------
    route = discover_eps_route(panda, CANDIDATE_BUSES, preferred_tx=ADDR)
    if route is None:
      result.update(status="unreachable", message=" ".join((
        "No EPS-like diagnostic responder was identified on bus 0, 1, or 2.",
        "Preserve the passive capture before changing the route hypotheses.",
      )))
      return result
    eps_tx = route["tx"]
    eps_bus = route["tx_bus"]
    eps_rx_bus = route["rx_bus"]
    eps_rx = route["rx"]
    result.update(eps_tx=f"0x{eps_tx:03x}", eps_bus=eps_bus,
                  eps_rx_bus=eps_rx_bus, eps_rx=f"0x{eps_rx:03x}")

    def ask_eps(payload: bytes, request_timeout: float) -> dict:
      return ask(panda, eps_bus, eps_tx, eps_rx, payload, request_timeout,
                 response_bus=eps_rx_bus)

    # --- calibrate the silence threshold ------------------------------------------
    samples = []
    for _ in range(CALIBRATION_SAMPLES):
      r = ask_eps(CALIBRATION_REQUEST, MAX_TIMEOUT)
      if r["outcome"] in ("positive", "nrc"):
        samples.append(r["ms"] / 1000.0)
    observed = sorted(samples)[len(samples) // 2] if samples else MIN_TIMEOUT
    timeout = min(MAX_TIMEOUT, max(MIN_TIMEOUT, observed * TIMEOUT_MULTIPLE))
    result["timeout_ms"] = int(timeout * 1000)
    stages.append({"name": "calibrate", "detail":
                   f"round trip {int(observed * 1000)} ms → timeout {int(timeout * 1000)} ms"})
    cb(steps=rec.count, last="calibrated", stage="calibrate")

    rec.write_event("route", tx=f"0x{eps_tx:03x}", rx=f"0x{eps_rx:03x}",
                    tx_bus=eps_bus, rx_bus=eps_rx_bus, probe_body=route["body"],
                    source=route.get("source", "unknown"))

    def discover_bus() -> bool:
      nonlocal eps_tx, eps_bus, eps_rx_bus, eps_rx
      rediscovered = discover_eps_route(panda, CANDIDATE_BUSES, preferred_tx=eps_tx,
                                        preferred_timeout=timeout * 4,
                                        scan_timeout=min(timeout, 0.1))
      if rediscovered is None:
        rec.write_event("route_probe", tx=f"0x{eps_tx:03x}", outcome="silent")
        return False
      eps_tx = rediscovered["tx"]
      eps_bus = rediscovered["tx_bus"]
      eps_rx_bus = rediscovered["rx_bus"]
      eps_rx = rediscovered["rx"]
      result.update(eps_tx=f"0x{eps_tx:03x}", eps_bus=eps_bus,
                    eps_rx_bus=eps_rx_bus, eps_rx=f"0x{eps_rx:03x}")
      rec.write_event("route_probe", tx=f"0x{eps_tx:03x}", rx=f"0x{eps_rx:03x}",
                      tx_bus=eps_bus, rx_bus=eps_rx_bus, outcome="response",
                      raw=rediscovered["body"], ms=rediscovered["ms"])
      return True

    def set_session(sf: int) -> dict:
      response = ask_eps(bytes([0x10, sf]), timeout)
      rec.write_event("session", request=f"10{sf:02x}", bus=eps_bus,
                      outcome=response["outcome"], nrc=response["nrc"],
                      raw=response["raw"], ms=response["ms"])
      return response

    def alive(after: str) -> bool:
      response = ask_eps(CALIBRATION_REQUEST, timeout * 4)
      rec.write_event("liveness", after=after, bus=eps_bus, outcome=response["outcome"],
                      nrc=response["nrc"], raw=response["raw"], ms=response["ms"])
      return response["outcome"] in ("positive", "nrc")

    def restore(reason: str) -> bool:
      outcomes = []
      for request in RESTORE_REQUESTS:
        response = ask_eps(request, timeout)
        outcomes.append(response["outcome"] in ("positive", "nrc"))
        rec.write_event("restore", reason=reason, request=request.hex(), bus=eps_bus,
                        outcome=response["outcome"], nrc=response["nrc"],
                        raw=response["raw"], ms=response["ms"])
      return any(outcomes)

    def recover_route(after: str) -> bool:
      if alive(after):
        return True
      rec.write_event("liveness_lost", after=after, bus=eps_bus)
      if not discover_bus():
        result["frontier"] = f"liveness lost after {after}; responder rediscovery failed"
        return False
      restore(f"rediscovered after {after}")
      return alive(f"rediscovery after {after}")

    def run_block(name, items, build, tx=None, tmo=None, session=None, stateful=False):
      """Run one resumable block, with keepalive and per-request state boundaries."""
      current_tx = eps_tx if tx is None else tx
      use = tmo if tmo is not None else timeout
      sent = 0
      last_keepalive = time.monotonic()
      for key, payload, label in (build(i) for i in items):
        if remaining() <= 0:
          result["frontier"] = f"{name}: stopped at {label}"
          return sent, False
        if rec.seen(key):
          continue
        if session and time.monotonic() - last_keepalive >= KEEPALIVE_INTERVAL:
          keepalive = (ask_eps(TESTER_PRESENT_REQUEST, timeout) if tx is None else
                       ask(panda, eps_bus, current_tx, rx_of(current_tx), TESTER_PRESENT_REQUEST, timeout))
          rec.write_event("tester_present", stage=name, session=session, bus=eps_bus,
                          outcome=keepalive["outcome"], nrc=keepalive["nrc"],
                          raw=keepalive["raw"], ms=keepalive["ms"])
          last_keepalive = time.monotonic()
        response = (ask_eps(payload, use) if tx is None else
                    ask(panda, eps_bus, current_tx, rx_of(current_tx), payload, use))
        rec.write(key, stage=name, session=session or "", label=label,
                  bus=eps_bus, tx=f"0x{current_tx:03x}",
                  rx=f"0x{eps_rx:03x}" if tx is None else f"0x{rx_of(current_tx):03x}",
                  request=payload.hex(), **{field: response[field]
                                           for field in ("outcome", "sid", "nrc", "raw", "ms")})
        sent += 1
        if stateful:
          restore(f"after {label}")
          if not recover_route(label):
            return sent, False
          if session == "extended":
            set_session(0x03)
        if needs_liveness_boundary(stateful, sent) and not stateful and not recover_route(label):
          return sent, False
        if sent % 16 == 0 or stateful:
          cb(steps=rec.count, last=label, stage=name)
      return sent, True

    # --- stage 1+2: every service byte, bare, in both sessions --------------------
    for session_name, sf in (("default", 0x01), ("extended", 0x03)):
      set_session(sf)
      n, finished = run_block(
        f"services/{session_name}", ordered_services(SERVICE_RANGE),
        lambda sid, _session=session_name: (f"svc:{_session}:{sid:02x}", bytes([sid]), f"service 0x{sid:02x}"),
        session=session_name)
      stages.append({"name": f"services/{session_name}", "detail": f"{n} sent"})
      cb(steps=rec.count, last=f"services {session_name}", stage="services")
      if not finished:
        break

    # Re-read the file to classify: which services answered, which stayed silent.
    answered_sids: set = set()
    silent_sids: set = set()
    try:
      with open(rec.path) as f:
        for line in f:
          try:
            r = json.loads(line)
          except Exception:
            continue
          if not r.get("key", "").startswith("svc:"):
            continue
          sid = int(r["key"].rsplit(":", 1)[1], 16)
          if r.get("outcome") in ("positive", "nrc") and r.get("nrc") != 0x11:
            answered_sids.add(sid)
          elif r.get("outcome") == "silent":
            silent_sids.add(sid)
    except FileNotFoundError:
      pass
    answering.extend(sorted(f"0x{s:02x}" for s in answered_sids))
    silent.extend(sorted(f"0x{s:02x}" for s in silent_sids))

    # --- stage 3: every sub-function of every service that answered ---------------
    # The boundary can run THROUGH a service rather than around it — 0x10 answers on
    # sub-functions 01/03/04 and is silent on 02 — so a service-level map alone misses it.
    if remaining() > 0:
      set_session(0x03)
      for sid in ordered_subfunction_services(answered_sids):
        if remaining() <= 0:
          result["frontier"] = f"subfunctions: stopped before service 0x{sid:02x}"
          break
        n, finished = run_block(
          f"subfunctions/{sid:02x}", ordered_subfunctions(sid),
          lambda s, _sid=sid: (f"sub:{_sid:02x}:{s:02x}", bytes([_sid, s]),
                               f"0x{_sid:02x} sub 0x{s:02x}"),
          session="extended", stateful=(sid == 0x10 or sid in STATEFUL_SERVICES))
        restore(f"after subfunction block 0x{sid:02x}")
        if not recover_route(f"subfunction block 0x{sid:02x}"):
          stages.append({"name": f"subfunctions/{sid:02x}",
                         "detail": f"{n} sent — EPS stopped answering after this service"})
          result["frontier"] = f"subfunctions: EPS died on service 0x{sid:02x}"
          break
        set_session(0x03)
        stages.append({"name": f"subfunctions/{sid:02x}", "detail": f"{n} sent"})
        cb(steps=rec.count, last=f"sub-functions of 0x{sid:02x}", stage="subfunctions")
        if not finished:
          break

    # --- stage 4: scoped DID pass -------------------------------------------------
    if remaining() > 0:
      set_session(0x03)
      for lo, hi, block in DID_BLOCKS:
        if remaining() <= 0:
          result["frontier"] = f"dids: stopped before block {block}"
          break
        n, finished = run_block(
          f"dids/{block}", range(lo, hi + 1),
          lambda d, _b=block: (f"did:{d:04x}", bytes([0x22, d >> 8, d & 0xFF]),
                               f"DID 0x{d:04x}"),
          session="extended")
        stages.append({"name": f"dids/{block}", "detail": f"{n} sent"})
        cb(steps=rec.count, last=f"DIDs {block}", stage="dids")
        if not finished:
          break

    # --- stage 5: discover request/response routes on every connected bus ---------
    if remaining() > 0:
      address_buses = [eps_bus] + [bus for bus in CANDIDATE_BUSES if bus != eps_bus]
      for a in ADDRESS_RANGE:
        if remaining() <= 0:
          result["frontier"] = f"addresses: stopped at 0x{a:03x}"
          break
        for candidate_bus in address_buses:
          key = f"addr:{candidate_bus}:{a:03x}"
          if rec.seen(key):
            continue
          route_hit = probe_response_route(panda, a, candidate_bus, b"\x10\x01", timeout)
          if route_hit is None:
            response = {"outcome": "silent", "sid": -1, "nrc": -1, "raw": "", "ms": int(timeout * 1000)}
            rec.write(key, stage="addresses", label=f"address 0x{a:03x} bus {candidate_bus}",
                      request="1001", tx=f"0x{a:03x}", tx_bus=candidate_bus,
                      rx="", rx_bus=-1, **response)
            continue
          parsed = parse_isotp_frame(bytes.fromhex(route_hit["body"])) or {
            "outcome": "positive", "sid": -1, "nrc": -1, "raw": route_hit["body"],
          }
          parsed["ms"] = route_hit["ms"]
          rec.write(key, stage="addresses", label=f"address 0x{a:03x} bus {candidate_bus}",
                    request="1001", tx=f"0x{a:03x}", tx_bus=candidate_bus,
                    rx=f"0x{route_hit['rx']:03x}", rx_bus=route_hit["rx_bus"], **parsed)

      # Rebuild discovered routes from the append-only transcript so resumed runs retain
      # responders found in an earlier five-minute window.
      route_by_key: dict[tuple[int, int], dict] = {}
      try:
        with open(rec.path, encoding="utf-8") as transcript:
          for line in transcript:
            try:
              row = json.loads(line)
              if not str(row.get("key", "")).startswith("addr:"):
                continue
              if row.get("outcome") not in ("positive", "nrc") or not row.get("rx"):
                continue
              tx = int(str(row.get("tx", "0")), 16)
              tx_bus = int(row.get("tx_bus", eps_bus))
              route_by_key[(tx_bus, tx)] = {
                "tx": tx, "tx_bus": tx_bus,
                "rx": int(str(row["rx"]), 16), "rx_bus": int(row.get("rx_bus", tx_bus)),
              }
            except (ValueError, TypeError, json.JSONDecodeError):
              continue
      except OSError:
        pass
      responders.extend(
        f"0x{route['tx']:03x}/b{route['tx_bus']}->0x{route['rx']:03x}/b{route['rx_bus']}"
        for route in sorted(route_by_key.values(), key=lambda item: (item["tx_bus"], item["tx"]))
      )
      result["responder_routes"] = list(route_by_key.values())
      stages.append({"name": "addresses", "detail": f"{len(responders)} responder route(s)"})
      cb(steps=rec.count, last="address sweep", stage="addresses")

      # Compare only bare services observed as silent in this calibration. Prior
      # Corolla reflash requests remain annotations and are not injected here.
      cross_requests = [(bytes([sid]), f"bare service 0x{sid:02x}")
                        for sid in sorted(silent_sids)]
      for route_key, responder_route in route_by_key.items():
        if route_key == (eps_bus, eps_tx) or remaining() <= 0:
          continue
        route_label = f"0x{responder_route['tx']:03x}/b{responder_route['tx_bus']}->0x{responder_route['rx']:03x}/b{responder_route['rx_bus']}"
        for payload, label in cross_requests:
          key = f"cross:{responder_route['tx_bus']}:{responder_route['tx']:03x}:{payload.hex()}"
          if rec.seen(key):
            continue
          response = ask(panda, responder_route["tx_bus"], responder_route["tx"],
                         responder_route["rx"], payload, timeout,
                         response_bus=responder_route["rx_bus"])
          rec.write(key, stage="cross", label=f"{route_label} {label}",
                    tx=f"0x{responder_route['tx']:03x}", tx_bus=responder_route["tx_bus"],
                    rx=f"0x{responder_route['rx']:03x}", rx_bus=responder_route["rx_bus"],
                    request=payload.hex(), **{field: response[field]
                                              for field in ("outcome", "sid", "nrc", "raw", "ms")})
          restore(f"after cross-ECU request {route_label} {label}")
          if not recover_route(f"cross-ECU request {route_label} {label}"):
            break
      cb(steps=rec.count, last="cross-ECU silent set", stage="cross")

    # --- stage 6: re-probe everything silent, at a much longer timeout ------------
    if remaining() > 0 and silent_sids:
      long_timeout = min(2.0, timeout * LONG_TIMEOUT_MULTIPLE)
      set_session(0x03)
      n, finished = run_block(
        "recheck", sorted(silent_sids),
        lambda sid: (f"recheck:{sid:02x}", bytes([sid]), f"recheck 0x{sid:02x}"),
        tmo=long_timeout, session="extended")
      stages.append({"name": "recheck", "detail": f"{n} sent at {int(long_timeout * 1000)} ms"})
      cb(steps=rec.count, last="recheck", stage="recheck")

    restore("final sweep restoration")
    result["records"] = rec.count
    if result["frontier"]:
      result.update(status="partial", message=" ".join((
        f"Budget reached — {rec.count} results saved. {result['frontier']}.",
        "Run this page again (Not Ready to Drive) and it resumes where it stopped.",
        "Export the evidence bundle before continuing.",
      )))
    else:
      result.update(status="complete", message=" ".join((
        f"Sweep finished — {rec.count} results saved, {len(answering)} service(s) answering,",
        f"{len(silent)} silent, {len(responders)} responder(s) on the bus.",
        "Export the evidence bundle before continuing.",
      )))
    return result

  except Exception as e:
    result.update(status="failed", records=rec.count,
                  message=f"Sweep aborted: {type(e).__name__}: {e} ({rec.count} results saved)")
    return result
  finally:
    rec.close()


def summarize(path: str = SWEEP_PATH) -> dict:
  """Pure — tally a persisted sweep. Off-device testable and shared with the READY pass,
  which builds its re-test work-list from these buckets."""
  out = {"records": 0, "positive": [], "nrc_11": [], "nrc_other": [], "silent": [],
         "responders": [], "condition_nrc": []}
  try:
    with open(path) as f:
      lines = f.readlines()
  except FileNotFoundError:
    return out
  for line in lines:
    try:
      r = json.loads(line)
    except Exception:
      continue
    key = r.get("key", "")
    if not key:
      continue
    out["records"] += 1
    label = r.get("label", key)
    outcome, nrc = r.get("outcome"), r.get("nrc", -1)
    if key.startswith("addr:") and outcome in ("positive", "nrc"):
      out["responders"].append(label)
      continue
    if outcome == "positive":
      out["positive"].append(label)
    elif outcome == "nrc" and nrc == 0x11:
      out["nrc_11"].append(label)
    elif outcome == "nrc":
      out["nrc_other"].append(label)
      if nrc in (0x22, 0x7E, 0x7F):
        out["condition_nrc"].append(label)
    elif outcome == "silent":
      out["silent"].append(label)
  return out
