#!/usr/bin/env python3
"""Application SecurityAccess 0x03/0x04 comparison probe.

The analyzed Sienna EPS 8965B4512000 has two independent SecurityAccess domains:

* bootloader 0x01/0x02 -> ``TSKExtractor.BOOT_SA_SECRET`` (f05f...)
* application 0x03/0x04 -> ``TSKExtractor.APPLICATION_03_04_SA_SECRET_8965B4512000``

Older TSKM code incorrectly sent the bootloader 0x01/0x02 secret against an
application 0x03/0x04 challenge, making the resulting NRC 0x35 uninformative.
This probe uses the correct application-domain secret.

A wrong SEND_KEY is a counted attempt. The probe therefore refuses to send it on a
cross-calibration target unless ``allow_cross_calibration=True`` is explicitly armed.
"""
from __future__ import annotations

import subprocess
import time

from tsk.lib.diagnostic_route import (
  AmbiguousDiagnosticRouteError, discover_eps_route_with_routing, route_fields,
)
from tsk.lib.dump_dataflash import ADDR, DUMP_START, KNOWN_KEY_OFFSET
from tsk.lib.dump_diag import CANDIDATE_BUSES
from tsk.lib.env import is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor

LONG_TIMEOUT = 3.0
SEED_LEVEL = 0x03
KEY_LEVEL = 0x04
SEED_DATA = b"\x00" * 16
ANALYZED_APPLICATION_ID = b"8965B4512000"

KEY_REGION = DUMP_START + KNOWN_KEY_OFFSET
READ_TARGETS = [("key region", KEY_REGION), ("dataflash base", DUMP_START)]


def _noop(**kwargs) -> None:
  pass


def _ascii(data: bytes) -> str:
  return "".join(chr(c) if 32 <= c < 127 else "." for c in data)


def send_sienna_application_key(progress_cb=None, *, allow_cross_calibration: bool = False) -> dict:
  """Test the 8965B4512000 application 0x03/0x04 key derivation once.

  Cross-calibration SEND_KEY requires explicit arming. Merely discovering the route,
  reading F181, entering EXTENDED, and requesting a seed are not counted-key writes.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop

  from Crypto.Cipher import AES
  from opendbc.car.uds import UdsClient, SESSION_TYPE, InvalidServiceIdError, MessageTimeoutError, NegativeResponseError
  try:
    from opendbc.car.uds import _negative_response_codes as NRC_TABLE
  except Exception:
    NRC_TABLE = {}

  reads: list = []
  result = {
    "status": "failed", "panda": "", "eps_bus": -1, "session": "", "seed": "",
    "key": "", "send_key": "", "post_unlock_reads": reads, "message": "",
    "target_f181": "", "target_f181_hex": "", "cross_calibration": False,
    "armed": bool(allow_cross_calibration),
  }

  def nrc(code) -> str:
    return f"NRC 0x{code:02x} {NRC_TABLE.get(code, 'unknown')}"

  subprocess.run(["pkill", "-9", "-f", "manager.py"], check=False)
  subprocess.run(["pkill", "-9", "-f", "pandad"], check=False)
  time.sleep(2)

  try:
    panda = TSKExtractor._connect_panda()
    try:
      ver = panda.get_version()
      result["panda"] = ver.decode(errors="replace") if isinstance(ver, (bytes, bytearray)) else str(ver)
    except Exception:
      result["panda"] = "unknown"
  except Exception as e:
    result["message"] = f"Connect failed: {type(e).__name__}: {e}"
    return result

  try:
    route = discover_eps_route_with_routing(panda, CANDIDATE_BUSES, preferred_tx=ADDR)
  except AmbiguousDiagnosticRouteError as e:
    result.update(status="failed", message=f"Ambiguous EPS diagnostic route: {e}")
    return result
  if route is None or route["tx_bus"] != route["rx_bus"]:
    result.update(status="unreachable", message="No same-bus EPS route was identified.")
    return result
  result.update(**route_fields(route))
  eps_bus = route["tx_bus"]

  def mk(timeout=LONG_TIMEOUT):
    return UdsClient(panda, route["tx"], route["rx"], eps_bus,
                     timeout=timeout, response_pending_timeout=timeout)

  # Identify the exact calibration before any counted key attempt.
  try:
    identity = bytes(mk(0.6).read_data_by_identifier(0xF181))
  except Exception as e:
    result.update(status="failed", message=f"Could not read F181 before SecurityAccess: {type(e).__name__}.")
    return result
  result["target_f181_hex"] = identity.hex()
  result["target_f181"] = _ascii(identity)
  exact_analyzed_target = ANALYZED_APPLICATION_ID in identity
  result["cross_calibration"] = not exact_analyzed_target
  cb(step="identity", last=result["target_f181"])

  if not exact_analyzed_target and not allow_cross_calibration:
    result.update(
      status="armed_required",
      message=("Target is not the analyzed 8965B4512000 calibration. No SEND_KEY was sent. " +
               "Explicitly arm the cross-calibration comparison to spend one counted 0x03/0x04 key attempt."),
    )
    return result

  u = mk()
  try:
    u.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    result["session"] = "extended"
  except NegativeResponseError as e:
    result["session"] = nrc(e.error_code)
  except Exception as e:
    result["session"] = type(e).__name__
  cb(step="extended", last="extended session")

  try:
    seed = bytes(u.security_access(SEED_LEVEL, data_record=SEED_DATA))
    result["seed"] = seed.hex()
  except NegativeResponseError as e:
    result.update(status="no_seed", message=f"Application seed request at 0x03 refused: {nrc(e.error_code)}.")
    return result
  except Exception as e:
    result.update(status="no_seed", message=f"Application seed request at 0x03 failed: {type(e).__name__}.")
    return result
  cb(step="seed", last=f"seed {result['seed'][:16]}")

  if len(seed) != 16:
    result.update(status="failed", message=f"Seed is {len(seed)} bytes, expected 16.")
    return result

  try:
    intermediate = AES.new(TSKExtractor.APPLICATION_03_04_SA_SECRET_8965B4512000,
                           AES.MODE_ECB).decrypt(SEED_DATA)
    response = AES.new(intermediate, AES.MODE_ECB).encrypt(seed)
    result["key"] = response.hex()
  except Exception as e:
    result.update(status="failed", message=f"Key computation failed: {type(e).__name__}.")
    return result
  cb(step="key", last="computed 8965B4512000 application 03/04 key")

  try:
    u.security_access(KEY_LEVEL, security_key=response)
    result["send_key"] = "accepted"
    result["status"] = "unlocked"
  except NegativeResponseError as e:
    result["send_key"] = nrc(e.error_code)
    if e.error_code == 0x35:
      result["status"] = "invalid_key"
    elif e.error_code in (0x36, 0x37):
      result["status"] = "locked"
    elif e.error_code == 0x33:
      result["status"] = "denied"
    else:
      result["status"] = "rejected"
  except (InvalidServiceIdError, MessageTimeoutError) as e:
    result["send_key"] = f"{type(e).__name__}" + (f": {e}" if str(e) else "")
    result["status"] = "failed"
  except Exception as e:
    result["send_key"] = type(e).__name__
    result["status"] = "failed"
  cb(step="send_key", last=f"send_key {result['send_key']}")

  if result["status"] == "unlocked":
    for name, addr in READ_TARGETS:
      entry = {"name": name, "address": f"0x{addr:08x}", "size": 16}
      try:
        data = bytes(u.read_memory_by_address(addr, 0x10))
        entry.update(ok=True, detail=data.hex())
      except NegativeResponseError as e:
        entry.update(ok=False, detail=nrc(e.error_code))
      except Exception as e:
        entry.update(ok=False, detail=type(e).__name__)
      reads.append(entry)
      cb(step="read", last=name)

  if result["status"] == "unlocked":
    result["message"] = ("8965B4512000 application 0x03/0x04 key derivation was accepted. " +
                         "Export the evidence bundle.")
  elif result["status"] == "invalid_key":
    result["message"] = ("The 8965B4512000 application 0x03/0x04 key derivation was rejected as invalid. " +
                         "For this target/session, the application secret or algorithm differs.")
  elif result["status"] == "locked":
    result["message"] = ("Application SecurityAccess is locked out (0x36/0x37). Power-cycle/re-enter the " +
                         "known safe state before another counted attempt.")
  elif result["status"] == "denied":
    result["message"] = "Application SEND_KEY was denied with NRC 0x33 in this session/state."
  else:
    result["message"] = f"Application SEND_KEY did not complete cleanly: {result['send_key']}."
  return result
