#!/usr/bin/env python3
"""Firmware-informed Toyota EPS programming-handoff probe.

This replaces the earlier matrix of speculative PROGRAMMING sequences. Static analysis
of Sienna 8965B4512000 established the useful discriminator:

* application PROGRAMMING is an asynchronous handoff;
* NRC 0x78 may be followed by reset before a final 0x50 0x02 is transmitted;
* application and bootloader keep the same EPS CAN controller/0x7A1->0x7A9 route;
* therefore a client timeout is not a refusal by itself.

The probe discovers an explicit ``(ELM327 param, logical bus, tx, rx)`` route, records
Panda health/CAN health, sends one DEFAULT -> EXTENDED -> PROGRAMMING transition, and
requires the endpoint to reappear on that exact physical route. No SecurityAccess key,
payload, download, or flash operation is sent.
"""
from __future__ import annotations

import subprocess
import time

from tsk.lib.diagnostic_route import (
  AmbiguousDiagnosticRouteError, SIENNA_FUNCTIONAL_ADDR, discover_eps_route_with_routing,
  probe_response_route, route_fields,
)
from tsk.lib.dump_diag import CANDIDATE_BUSES
from tsk.lib.env import is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.programming import ProgrammingHandoffError, enter_programming_bootloader, uds_client

ADDR = TSKExtractor.ADDR
FUNCTIONAL_ADDR = SIENNA_FUNCTIONAL_ADDR  # firmware-verified only for 8965B4512000


def _noop(**kwargs) -> None:
  pass


def _ascii(data: bytes) -> str:
  return "".join(chr(c) if 32 <= c < 127 else "." for c in data)


def _read_f181(panda, route: dict) -> dict:
  try:
    data = bytes(uds_client(panda, route, timeout=0.5, response_pending_timeout=1.0)
                 .read_data_by_identifier(0xF181))
    return {"hex": data.hex(), "ascii": _ascii(data)}
  except Exception as e:
    return {"hex": "", "ascii": type(e).__name__}


def _functional_probe(panda, route: dict) -> dict:
  """Calibration-scoped check of the Sienna 0x777 functional endpoint."""
  hit = probe_response_route(panda, FUNCTIONAL_ADDR, route["tx_bus"], b"\x10\x01", timeout=0.3)
  if hit is None:
    return {"address": f"0x{FUNCTIONAL_ADDR:03x}", "observed": False}
  return {
    "address": f"0x{FUNCTIONAL_ADDR:03x}",
    "observed": True,
    "rx": f"0x{hit['rx']:03x}",
    "rx_bus": hit["rx_bus"],
    "body": hit["body"],
  }


def probe_programming(progress_cb=None) -> dict:
  """Run one controlled application -> bootloader transition.

  Result keeps the historical top-level fields used by the web UI, while the useful
  data now lives in ``route``, ``application_f181``, ``programming_handoff``,
  ``bootloader_f181``, and the calibration-scoped ``functional_0x777`` checks.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop
  attempts: list[dict] = []
  result = {
    "status": "failed",
    "panda": "",
    "eps_bus": -1,
    "attempts": attempts,
    "security": {},
    "security_levels": [],
    "did_it_take": {},
    "all_bus": [],
    "route": {},
    "application_f181": {},
    "bootloader_f181": {},
    "functional_0x777": {},
    "programming_handoff": {},
    "message": "",
  }

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

  cb(attempts=0, last="discover physical route")
  try:
    route = discover_eps_route_with_routing(panda, CANDIDATE_BUSES, preferred_tx=ADDR)
  except AmbiguousDiagnosticRouteError as e:
    result.update(status="failed", message=f"Ambiguous EPS diagnostic route: {e}")
    return result
  if route is None:
    result.update(status="unreachable",
                  message="No EPS-like responder answered under normal-harness or OBD routing.")
    return result

  result.update(**route_fields(route))
  result["route"] = route_fields(route)
  result["application_f181"] = _read_f181(panda, route)
  functional_before = _functional_probe(panda, route)
  result["functional_0x777"] = {"before": functional_before}
  attempts.append({
    "name": "route discovery",
    "ok": True,
    "detail": str(route_fields(route)),
    "programming": False,
  })
  cb(attempts=len(attempts), last="route discovered")

  started = time.monotonic()
  try:
    boot_route, telemetry = enter_programming_bootloader(
      panda, route, prepare_sessions=True, settle_extended=0.7, reappearance_timeout=6.0,
    )
  except ProgrammingHandoffError as e:
    telemetry = e.telemetry
    result["programming_handoff"] = telemetry
    detail = f"NRC 0x{e.nrc:02x}" if e.nrc is not None else str(e)
    attempts.append({
      "name": "DEFAULT -> EXTENDED -> PROGRAMMING",
      "ok": False,
      "detail": detail,
      "programming": True,
      "ms": int((time.monotonic() - started) * 1000),
    })
    cb(attempts=len(attempts), last="programming handoff failed")
    result["status"] = "blocked"
    if e.nrc == 0x88:
      result["message"] = ("PROGRAMMING was explicitly rejected with NRC 0x88 (vehicleSpeedTooHigh). " +
                           "The analyzed Sienna application uses this exact speed guard.")
    elif e.nrc == 0x22:
      result["message"] = ("PROGRAMMING was explicitly rejected with NRC 0x22 (conditionsNotCorrect). " +
                           "On analyzed Sienna firmware this can be the system-transition/supply/handoff gate; " +
                           "do not interpret it as a routing failure.")
    elif e.nrc is not None:
      result["message"] = f"PROGRAMMING was explicitly rejected with NRC 0x{e.nrc:02x}."
    else:
      result["message"] = ("No explicit rejection was received, but the EPS did not reappear on the preserved " +
                           "physical route. Inspect programming_handoff.health_* for ACK/bus-off/CAN-core evidence.")
    return result

  result["programming_handoff"] = telemetry
  result.update(**route_fields(boot_route))
  result["route"] = route_fields(boot_route)
  result["bootloader_f181"] = _read_f181(panda, boot_route)
  result["functional_0x777"]["after"] = _functional_probe(panda, boot_route)
  result["did_it_take"] = {
    "switched": True,
    "evidence": "diagnostic endpoint reappeared on preserved route after application PROGRAMMING reset",
    "response_timeout": bool(telemetry.get("programming_response_timeout")),
  }
  attempts.append({
    "name": "DEFAULT -> EXTENDED -> PROGRAMMING",
    "ok": True,
    "detail": ("endpoint reappeared on preserved route"
               + (" after response timeout" if telemetry.get("programming_response_timeout") else "")),
    "programming": True,
    "ms": int((time.monotonic() - started) * 1000),
  })
  cb(attempts=len(attempts), last="bootloader reappeared")
  result["status"] = "entered"
  result["message"] = (
    "Programming handoff completed: the EPS reappeared on the same explicit Panda physical route. " +
    "A missing final 0x50 0x02 is therefore not treated as failure. Export the evidence bundle."
  )
  return result
