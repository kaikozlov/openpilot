#!/usr/bin/env python3
"""Read-only application SID 0x23 characterization for Toyota/Denso EPS targets.

The analyzed Sienna 8965B4512000 does expose ReadMemoryByAddress in EXTENDED
session without SecurityAccess, but it does *not* use opendbc's ordinary
four-byte-address request shape. Its only accepted ALFID is 0x15:

  23 15 <memory-id:1> <absolute-address:4-byte-be> <size:1>

Memory ID 1 selects LocalRAM and memory ID 2 selects DataFlash. This distinction
matters: the historical TSK probe used ``UdsClient.read_memory_by_address()``,
which emits ALFID 0x14 and therefore could falsely report that the known Sienna
service was blocked.

This probe remains observation-only. It sends no write service, SecurityAccess
key, reset, RoutineControl, RequestDownload, or XCP memory-write command. For an
unknown calibration it tries both the firmware-derived memory-ID shape and the
ordinary ISO-style shape so a negative result is not caused by assuming either
request grammar.
"""
from __future__ import annotations

import subprocess
import time

from tsk.lib.diagnostic_route import discover_eps_route_with_routing, route_fields
from tsk.lib.env import is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.dump_dataflash import ADDR, DUMP_START, KNOWN_KEY_OFFSET
from tsk.lib.dump_diag import CANDIDATE_BUSES
from tsk.lib.ram_exec_geometry import normalize_f181

ALFID_MEMORY_ID = 0x15
RAM_ID = 1
DATAFLASH_ID = 2
MAX_MEMORY_ID_READ = 0xFF
READ_TIMEOUT = 1.0

KEY_ADDR = DUMP_START + KNOWN_KEY_OFFSET       # 0xFF206E14; protected on 8965B4512000
BOOT_PAYLOAD_KEY_RESIDUE = 0xFEBF2D08         # bootloader DID 0x0201 input buffer
ACTUATION_OBSERVATION = 0xFEBE6D28            # recovered d/q-reference observation bytes

# KEYLESS-006: on these exact tracked images, normal application startup copies the
# complete application 0x03/0x04 SecurityAccess root into a LocalRAM interval that
# SID 0x23 can read in EXTENDED session without SecurityAccess.  Keep this exact-F181
# keyed: a family/prefix match is not evidence that another calibration uses the same
# destination or read exclusions.
APPLICATION_SA_ROOT_EXPECTED = bytes.fromhex("893e08418c741ffa2a9c044bffa55813")
APPLICATION_SA_MIRRORS = {
  "8965B4512000": 0xFEBF7BE0,
  "8965H1202000": 0xFEBF7B80,
  "8965F1208000": 0xFEBF7B80,
}


def application_sa_mirror_for_f181(f181: bytes | bytearray | str) -> int | None:
  return APPLICATION_SA_MIRRORS.get(normalize_f181(f181))


def application_sa_recovery_plan(f181: bytes | bytearray | str) -> dict:
  normalized = normalize_f181(f181)
  address = APPLICATION_SA_MIRRORS.get(normalized)
  return {
    "f181": normalized,
    "supported": address is not None,
    "address": f"0x{address:08x}" if address is not None else "",
    "memory_id": RAM_ID if address is not None else None,
    "size": len(APPLICATION_SA_ROOT_EXPECTED) if address is not None else 0,
    "expected_root": APPLICATION_SA_ROOT_EXPECTED.hex() if address is not None else "",
    "evidence": "KEYLESS-006 exact-F181 startup LocalRAM mirror" if address is not None else "",
  }

# Firmware-verified 8965B4512000 service policy. These are used to annotate the
# result, not to suppress cross-calibration read attempts: another target may have
# different exclusions and that difference is useful evidence.
SIENNA_RAM_RANGE = (0xFEBE0000, 0xFEBFFFFF)
SIENNA_DATAFLASH_RANGE = (0xFF200000, 0xFF207FFF)
SIENNA_RAM_EXCLUDED = (
  (0xFEBE0000, 0xFEBE37FF),
  (0xFEBE5030, 0xFEBE529B),
  (0xFEBF0288, 0xFEBF13CB),
  (0xFEBF4958, 0xFEBF4B33),
  (0xFEBF6C00, 0xFEBF78DF),
)
SIENNA_DATAFLASH_EXCLUDED = (
  (0xFF206C00, 0xFF206EFF),
  (0xFF207800, 0xFF207FFF),
)

# label, request shape, memory ID, address, size. The first four exercise the
# exact 8965B4512000 grammar. The final ordinary request keeps the probe useful on
# an unknown calibration that follows the common ISO-style ALFID 0x14 shape.
TARGETS = (
  ("dataflash base", "memory-id", DATAFLASH_ID, DUMP_START, 0x10),
  ("object-15 / historical key region", "memory-id", DATAFLASH_ID, KEY_ADDR, 0x10),
  ("boot payload-key residue", "memory-id", RAM_ID, BOOT_PAYLOAD_KEY_RESIDUE, 0x10),
  ("d/q observation bytes", "memory-id", RAM_ID, ACTUATION_OBSERVATION, 0x04),
  ("legacy no-memory-id key region", "ordinary", None, KEY_ADDR, 0x10),
)


def _noop(**kwargs) -> None:
  pass


def _overlaps(address: int, size: int, ranges) -> bool:
  end = address + size - 1
  return any(address <= high and low <= end for low, high in ranges)


def sienna_policy(memory_id: int, address: int, size: int) -> str:
  """Return the 8965B4512000 static disposition for one memory-ID read."""
  if size <= 0:
    return "invalid"
  base = SIENNA_RAM_RANGE if memory_id == RAM_ID else SIENNA_DATAFLASH_RANGE if memory_id == DATAFLASH_ID else None
  excluded = SIENNA_RAM_EXCLUDED if memory_id == RAM_ID else SIENNA_DATAFLASH_EXCLUDED if memory_id == DATAFLASH_ID else ()
  if base is None:
    return "unknown-memory-id"
  end = address + size - 1
  if address < base[0] or end > base[1] or end < address:
    return "outside-range"
  if _overlaps(address, size, excluded):
    return "firmware-excluded"
  return "firmware-readable"


def memory_id_request_data(memory_id: int, address: int, size: int) -> bytes:
  """Build the exact 8965B4512000 SID-0x23 request data after the service byte."""
  if memory_id not in (RAM_ID, DATAFLASH_ID):
    raise ValueError("memory ID must be 1 (LocalRAM) or 2 (DataFlash)")
  if not 1 <= size <= MAX_MEMORY_ID_READ:
    raise ValueError("memory-ID read size must be 1..255 bytes")
  if not 0 <= address <= 0xFFFFFFFF or address + size - 1 > 0xFFFFFFFF:
    raise ValueError("memory-ID read address must be a non-wrapping 32-bit range")
  return bytes((ALFID_MEMORY_ID, memory_id)) + address.to_bytes(4, "big") + bytes((size,))


def read_memory_with_id(uds_client, service_type, memory_id: int, address: int, size: int) -> bytes:
  payload = uds_client._uds_request(
    service_type.READ_MEMORY_BY_ADDRESS,
    subfunction=None,
    data=memory_id_request_data(memory_id, address, size),
  )
  result = bytes(payload)
  if len(result) != size:
    raise ValueError(f"SID 0x23 returned {len(result)} bytes; expected {size}")
  return result


def read_key_region(progress_cb=None) -> dict:
  """Characterize direct application SID-0x23 reads without modifying ECU state.

  Returns ``{status, panda, route..., f181, reads[], message}``. ``status`` is
  ``read`` when at least one target returned bytes, ``denied`` when every request
  was refused/timed out, ``unreachable`` when no same-bus EPS route was found, or
  ``failed`` for a local/tooling failure.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop

  from opendbc.car.uds import UdsClient, SESSION_TYPE, SERVICE_TYPE, \
    InvalidServiceIdError, MessageTimeoutError, NegativeResponseError
  try:
    from opendbc.car.uds import _negative_response_codes as NRC_TABLE
  except Exception:
    NRC_TABLE = {}

  reads: list[dict] = []
  result = {
    "status": "failed", "panda": "", "eps_bus": -1, "f181": "", "f181_hex": "",
    "reads": reads, "application_sa_recovery": {}, "message": "",
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

  route = discover_eps_route_with_routing(panda, CANDIDATE_BUSES, preferred_tx=ADDR)
  if route is None or route["tx_bus"] != route["rx_bus"]:
    result.update(status="unreachable", message="No same-bus EPS route answered under normal-harness or OBD routing.")
    return result
  result.update(**route_fields(route))
  eps_bus = route["tx_bus"]
  identity = bytes.fromhex(str(route.get("identity", ""))) if route.get("identity") else b""
  result["f181_hex"] = identity.hex()
  result["f181"] = "".join(chr(c) if 32 <= c < 127 else "." for c in identity)
  app_sa_plan = application_sa_recovery_plan(identity)
  result["application_sa_recovery"] = dict(app_sa_plan)

  def mk():
    return UdsClient(panda, route["tx"], route["rx"], eps_bus,
                     timeout=READ_TIMEOUT, response_pending_timeout=READ_TIMEOUT)

  def do_read(name: str, shape: str, memory_id: int | None, address: int, size: int) -> None:
    u = mk()
    entry = {
      "name": name,
      "session": "extended",
      "shape": shape,
      "memory_id": memory_id,
      "address": f"0x{address:08x}",
      "size": size,
      "sienna_8965b4512000_policy": sienna_policy(memory_id, address, size) if memory_id is not None else "different-alfid",
    }
    try:
      u.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
      if shape == "memory-id":
        data = read_memory_with_id(u, SERVICE_TYPE, int(memory_id), address, size)
        entry["request_data"] = memory_id_request_data(int(memory_id), address, size).hex()
      else:
        data = bytes(u.read_memory_by_address(address, size))
        entry["request_data"] = (bytes((0x14,)) + address.to_bytes(4, "big") + bytes((size,))).hex()
      entry.update(ok=True, detail=bytes(data).hex())
    except NegativeResponseError as e:
      entry.update(ok=False, detail=nrc(e.error_code))
    except (InvalidServiceIdError, MessageTimeoutError) as e:
      entry.update(ok=False, detail=f"{type(e).__name__}: {e}" if str(e) else type(e).__name__)
    except Exception as e:
      entry.update(ok=False, detail=f"{type(e).__name__}: {e}" if str(e) else type(e).__name__)
    reads.append(entry)
    cb(reads=len(reads), last=f"{name} ({shape})")

  for target in TARGETS:
    do_read(*target)
  app_sa_address = application_sa_mirror_for_f181(identity)
  if app_sa_address is not None:
    do_read("application SecurityAccess root mirror", "memory-id", RAM_ID, app_sa_address,
            len(APPLICATION_SA_ROOT_EXPECTED))

  got = [row for row in reads if row["ok"]]
  app_sa_row = next((row for row in reads if row["name"] == "application SecurityAccess root mirror"), None)
  if app_sa_row is not None:
    recovered = app_sa_row.get("detail", "") if app_sa_row.get("ok") else ""
    result["application_sa_recovery"].update(
      attempted=True,
      recovered_root=recovered,
      matches_expected=bool(recovered and recovered.lower() == APPLICATION_SA_ROOT_EXPECTED.hex()),
      read_ok=bool(app_sa_row.get("ok")),
    )
  else:
    result["application_sa_recovery"].update(
      attempted=False, recovered_root="", matches_expected=False, read_ok=False,
    )
  result["status"] = "read" if got else "denied"
  exact = [row for row in got if row["shape"] == "memory-id"]
  residue = next((row for row in exact if row["name"] == "boot payload-key residue"), None)
  app_sa = result["application_sa_recovery"]
  if app_sa.get("read_ok") and app_sa.get("matches_expected"):
    result["message"] = " ".join((
      "The exact-F181 KEYLESS-006 application SecurityAccess mirror was read before SecurityAccess",
      "and matches the firmware-pinned 0x03/0x04 root. No SEND_KEY or write was sent.",
      "The independent bootloader 0x01/0x02 SecurityAccess root is not disclosed by this read.",
    ))
  elif app_sa.get("read_ok"):
    result["message"] = " ".join((
      "The exact-F181 application SecurityAccess mirror was readable, but its 16 bytes differ from",
      "the firmware-pinned root for this tracked image. Preserve the evidence and do not send a key",
      "until the target identity/provenance is re-checked.",
    ))
  elif residue is not None:
    result["message"] = " ".join((
      "The firmware-derived memory-ID SID 0x23 path is live, including FEBF2D08.",
      "Those 16 bytes are the bootloader DID-0201 payload-key input buffer; preserve this result",
      "to determine whether useful bootloader residue survives application handoff.",
    ))
  elif exact:
    result["message"] = " ".join((
      "The firmware-derived ALFID 0x15 / memory-ID SID 0x23 path returned data.",
      "This is an unauthenticated application disclosure surface; export the evidence bundle.",
    ))
  elif got:
    result["message"] = " ".join((
      "Only the ordinary no-memory-ID SID 0x23 shape returned data. This target differs from the",
      "8965B4512000 request grammar; preserve the exact response for calibration-specific analysis.",
    ))
  else:
    result["message"] = " ".join((
      "Neither the firmware-derived ALFID 0x15 memory-ID form nor the ordinary ALFID 0x14 form",
      "returned bytes on this target. This is a target-specific negative, not evidence that",
      "8965B4512000 lacks SID 0x23.",
    ))
  return result
