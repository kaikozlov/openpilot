#!/usr/bin/env python3
import json
import mimetypes
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

from tsk.lib.collect_can import collect as collect_can, count_oracle_frames, oracle_path as can_oracle_path, PROTECTED_TARGET, SYNC_TARGET
from tsk.lib.camry_f33 import CAMRY_F33_PRIMARY_SW, public_camry_f33_status
from tsk.lib.secoc_discovery import load_oracle_discovery
from tsk.lib.secoc_profile import CURRENT_OPENPILOT_LATERAL_PROTECTED_ADDRS, CURRENT_OPENPILOT_LONGITUDINAL_PROTECTED_ADDRS
from tsk.lib.dump_dataflash import (
  AUTORESET_PAYLOAD_SHA256 as DATAFLASH_AUTORESET_PAYLOAD_SHA256,
  DUMP_TOTAL, PAYLOAD_SHA256 as DATAFLASH_PAYLOAD_SHA256, dump as dump_dataflash, dump_path,
  partial_coverage_path, partial_dump_path,
)
from tsk.lib.env import is_agnos
from tsk.lib.evidence import create_evidence_bundle, record_operation
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.key_file_manager import KeyFileManager, format_key
from tsk.lib.recovered_key import persist_recovered_key, public_recovered_key_status, recovered_key_hex
from tsk.lib.reboot_manager import REBOOT_ACTIONS, RebootManager
from tsk.lib.ram_exec_geometry import known_ram_exec_geometry, normalize_f181
from tsk.lib.bootstrap_profile import RAM_DUMP_FIXTURE_SHA256, fixture_is_evidenced, public_bootstrap_status
from tsk.lib.ephemeral_runtime import (
  EphemeralRuntimeError, import_runtime_package_json, public_runtime_status, run_inert_canary,
)
from tsk.lib.sniff_can import sniff as sniff_can, summarize_counts
from tsk.lib.dump_diag import diagnose as dump_diagnose
from tsk.lib.prog_probe import probe_programming
from tsk.lib.read_mem import read_key_region
from tsk.lib.xcp_observer import FORBIDDEN_COMMANDS as XCP_FORBIDDEN_COMMANDS, PROFILES as XCP_PROFILES, probe_xcp
from tsk.lib.ident_map import map_surface
from tsk.lib.integration_profile import manifest_template as integration_manifest_template, save_and_refresh as save_integration_and_refresh
from tsk.lib.reset_probe import probe_reset_window
from tsk.lib.level3_probe import probe_level3
from tsk.lib.sendkey_probe import send_sienna_application_key
from tsk.lib.preamble_probe import probe_preamble
from tsk.lib.sweep_uds import sweep
from tsk.lib.capture_ready import capture_ready, run_ready_diff
from tsk.lib.target_profile import (
  invalidate_target_profile, persist_target_profile, public_target_profile_status,
  refresh_target_profile_from_recovered,
)
from tsk.lib.stationary_verification import stationary_plan, verify_and_refresh as verify_stationary_and_refresh


HOST = "0.0.0.0"
PORT = 11111
ASSET_DIR = Path(__file__).resolve().with_name("static")
OFFROAD_ALERT_PARAM = "Offroad_NoFirmware"
OFFROAD_ALERT_INTERVAL = 5.0

# Shared tail for the unexpected-error surfaces (extract + match). The leading
# "!!!!" makes index.html's modal render it red; the extractor terminal prints it
# verbatim. Kept in one place so the two paths can't drift.
PING_REPORT = ("!!!! Unexpected error. Preserve the raw logs and export the " +
               "evidence bundle before continuing.")

READY_OPERATIONS = {"/api/can-collect", "/api/ready-capture", "/api/ready-diff"}
NRTD_OPERATIONS = {
  "/api/extract", "/api/dataflash-dump", "/api/dataflash-diag", "/api/prog-probe",
  "/api/read-mem", "/api/xcp-observer", "/api/ident-map", "/api/reset-probe", "/api/level3-probe",
  "/api/sendkey-probe", "/api/preamble-probe", "/api/uds-sweep", "/api/ephemeral-canary",
}


def expected_vehicle_state(operation: str) -> str:
  if operation in READY_OPERATIONS:
    return "READY (operator-asserted by selected workflow)"
  if operation in NRTD_OPERATIONS:
    return "Not Ready to Drive (operator-asserted by selected workflow)"
  return "unspecified"


last_alert_url: str | None = None
# One physical panda: extract, dump, and collect must not run concurrently. Held
# for the whole operation (extract in the request thread; dump/collect in their
# job threads, released in the job's finally).
panda_lock = threading.Lock()
matcher_lock = threading.Lock()


def append_address(addresses: list[str], ip: str) -> None:
  if ip and not ip.startswith("127.") and ip not in addresses:
    addresses.append(ip)


def get_ipv4_addresses() -> list[str]:
  addresses: list[str] = []

  try:
    output = subprocess.check_output(
      ["ip", "-o", "-4", "route", "get", "1.1.1.1"],
      encoding="utf-8",
      stderr=subprocess.DEVNULL,
      timeout=1.0,
    )
    parts = output.split()
    if "src" in parts:
      append_address(addresses, parts[parts.index("src") + 1])
  except (OSError, subprocess.SubprocessError, TimeoutError):
    pass

  try:
    for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
      append_address(addresses, info[4][0])
  except OSError:
    pass

  # AGNOS devices have the `ip` utility, and it tends to be more accurate than
  # hostname lookups for hotspot and garage Wi-Fi testing.
  try:
    output = subprocess.check_output(
      ["ip", "-o", "-4", "addr", "show", "scope", "global"],
      encoding="utf-8",
      stderr=subprocess.DEVNULL,
      timeout=1.0,
    )
    for line in output.splitlines():
      parts = line.split()
      if "inet" not in parts:
        continue

      cidr = parts[parts.index("inet") + 1]
      append_address(addresses, cidr.split("/", 1)[0])
  except (OSError, subprocess.SubprocessError, TimeoutError):
    pass

  return addresses


def get_tsk_url() -> str | None:
  addresses = get_ipv4_addresses()
  return f"http://{addresses[0]}:{PORT}" if addresses else None


def get_params_dir() -> Path:
  params_root = Path(os.getenv("PARAMS_ROOT", "/data/params"))
  params_prefix = os.getenv("OPENPILOT_PREFIX", "d") or "d"
  return params_root / params_prefix


def get_reboot_actions_payload() -> dict:
  reboot_manager = RebootManager()
  payload = {
    "is_agnos": is_agnos(),
    "dry_run": not reboot_manager.is_agnos,
  }
  payload.update(reboot_manager.actions_payload())
  return payload


def run_reboot_action(action: str) -> tuple[HTTPStatus, dict]:
  if action not in REBOOT_ACTIONS:
    return HTTPStatus.BAD_REQUEST, {
      "ok": False,
      "error": "bad_action",
      "title": "Unknown action",
      "message": f"Unknown reboot action: {action}",
      **RebootManager.key_status_payload(),
    }

  try:
    return HTTPStatus.OK, RebootManager().execute(action)
  except Exception as e:
    return HTTPStatus.INTERNAL_SERVER_ERROR, {
      "ok": False,
      "error": "unexpected",
      "title": "Unexpected error",
      "message": str(e),
      "traceback": traceback.format_exc(),
      **RebootManager.key_status_payload(),
    }


def write_offroad_alert(url: str | None) -> bool:
  params_dir = get_params_dir()
  if not params_dir.exists():
    return False

  alert_path = params_dir / OFFROAD_ALERT_PARAM
  if url is None:
    try:
      alert_path.unlink()
    except FileNotFoundError:
      pass
    return True

  payload = json.dumps({"text": "%1", "severity": 0, "extra": url}, sort_keys=True)
  tmp_path = params_dir / f".tmp_{OFFROAD_ALERT_PARAM}_{os.getpid()}"

  with open(tmp_path, "w", encoding="utf-8") as f:
    f.write(payload)
    f.flush()
    os.fsync(f.fileno())

  os.replace(tmp_path, alert_path)

  try:
    dir_fd = os.open(params_dir, os.O_RDONLY)
    try:
      os.fsync(dir_fd)
    finally:
      os.close(dir_fd)
  except OSError:
    pass

  return True


def update_offroad_alert() -> None:
  global last_alert_url

  url = get_tsk_url()
  # The manager wipes Offroad_NoFirmware on start (CLEAR_ON_MANAGER_START) and on
  # the onroad transition, out from under us. Rewrite when the URL changed or the
  # file is gone — trusting last_alert_url alone masks the deletion and the alert
  # never returns.
  alert_path = get_params_dir() / OFFROAD_ALERT_PARAM
  if url == last_alert_url and (url is None or alert_path.exists()):
    return

  try:
    if write_offroad_alert(url):
      last_alert_url = url
  except OSError as e:
    print(f"TSK Manager Web could not update offroad alert: {e}", flush=True)


def offroad_alert_loop() -> None:
  while True:
    update_offroad_alert()
    time.sleep(OFFROAD_ALERT_INTERVAL)


def resolve_asset(path: str) -> Path | None:
  relative_path = "index.html" if path in ("", "/") else unquote(path).lstrip("/")
  if relative_path.endswith("/"):
    relative_path += "index.html"

  relative = Path(relative_path)
  if relative.is_absolute() or ".." in relative.parts:
    return None

  candidate = (ASSET_DIR / relative).resolve()
  try:
    candidate.relative_to(ASSET_DIR.resolve())
  except ValueError:
    return None

  if candidate.is_file():
    return candidate

  return None


def content_type_for(path: Path) -> str:
  content_type, _ = mimetypes.guess_type(path.name)
  content_type = content_type or "application/octet-stream"
  if content_type.startswith("text/") or content_type in ("application/javascript", "application/json"):
    content_type += "; charset=utf-8"
  return content_type


DRY_RUN_FAKE_KEY = "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8"
dry_run_counter = 0

# CAN collection runs as a background job, mirroring the DataFlash job below.
# can_state is the live progress the status endpoint reports; the collect thread
# owns writes under can_lock. ready == (status == "complete").
can_lock = threading.Lock()
can_state = {
  "ready": False,
  "status": "idle",   # idle | running | complete | insufficient | failed
  "sync_count": 0,
  "protected_count": 0,
  "protected_by_id": {},
  "counts_by_bus": {},
  "legacy_lateral_observed": False,
  "legacy_lateral_counts": {},
  "legacy_longitudinal_observed": False,
  "legacy_longitudinal_counts": {},
  "profile_discovery": {},
  "elm327_param": -1,
  "semantic_path": "",
  "seconds": 0.0,
  "message": "",
}

# DataFlash dump runs as a background job. df_state is the live progress the
# status endpoint reports; the dump thread owns writes to it under df_lock.
# ready == (status == "complete") so the UI's existing green-dot gating holds.
df_lock = threading.Lock()
df_state = {
  "ready": False,
  "status": "idle",   # idle | running | complete | partial | unusable_partial | failed
  "frames": 0,
  "bytes": 0,
  "total": DUMP_TOTAL,
  "message": "",
  "size": 0,
  "payload_variant": "standard",
  "coverage_path": "",
  "longest_covered_run": 0,
  "known_key_window_covered": False,
  "application_f181": "",
  "ram_exec_geometry": {},
  "route": {},
  "programming_handoff": {},
}

# CAN sniffer runs as a background job like the others. Read-only diagnostic: it
# tallies raw traffic per bus and writes no file, so there is nothing to rehydrate.
sniff_lock = threading.Lock()
sniff_state = {
  "status": "idle",   # idle | running | complete | failed
  "seconds": 0.0,
  "frames": 0,
  "bus_count": 0,
  "total": 0,
  "buses": [],
  "markers": [],
  "fd_buses": [],
  "message": "",
}

# Instrumented DataFlash payload diagnostic. Unknown targets may be observed through the
# programming handoff, bootloader identity, and seed request. Counted SEND_KEY and actual
# payload writes retain their separate arming/evidence boundaries.
diag_lock = threading.Lock()
diag_state = {
  "status": "idle",   # idle | running | observed | dumped | no_frames | rejected | failed
  "step_count": 0,
  "last": "",
  "panda": "",
  "eps_bus": -1,
  "identity": [],
  "bootloader_identity": [],
  "ram_exec_geometry": {},
  "security_seed": "",
  "send_key_armed": False,
  "cross_calibration_send_key": False,
  "steps": [],
  "failed_at": "",
  "exception": "",
  "traceback": "",
  "frames": 0,
  "bytes": 0,
  "message": "",
}

# Firmware-informed programming handoff probe. One controlled DEFAULT -> EXTENDED ->
# PROGRAMMING transition is judged by endpoint reappearance on the preserved physical
# route, with Panda/CAN health captured around the reset.
probe_lock = threading.Lock()
probe_state = {
  "status": "idle",   # idle | running | entered | blocked | unreachable | failed
  "attempt_count": 0,
  "last": "",
  "panda": "",
  "eps_bus": -1,
  "attempts": [],
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

# ReadMemoryByAddress (0x23) probe — exact memory-ID grammar plus a legacy-shape comparison.
readmem_lock = threading.Lock()
readmem_state = {
  "status": "idle",   # idle | running | read | denied | unreachable | failed
  "count": 0,
  "last": "",
  "panda": "",
  "eps_bus": -1,
  "f181": "",
  "f181_hex": "",
  "reads": [],
  "application_sa_recovery": {},
  "message": "",
}

# Bounded application XCP observer. F4 reads and volatile DAQ configuration may run on
# unknown targets after CONNECT; 8965B4512000-derived address semantics are exact-F181 only.
xcp_lock = threading.Lock()
xcp_state = {
  "status": "idle",   # idle | running | reachable | observed | unreachable | failed
  "count": 0,
  "last": "",
  "step": "",
  "panda": "",
  "eps_bus": -1,
  "eps_rx_bus": -1,
  "eps_tx": "",
  "eps_rx": "",
  "f181": "",
  "f181_hex": "",
  "schema": "tsk-xcp-daq-observer-v2",
  "profile": "actuation-discriminator",
  "profile_description": "",
  "profile_finding_ids": [],
  "xcp_request_id": "0x7f7",
  "xcp_response_id": "0x7f8",
  "connect_response": "",
  "snapshot": [],
  "frames": [],
  "profile_semantics_verified": False,
  "profile_semantics": "",
  "volatile_daq_configuration": True,
  "source_memory_writes_implemented": False,
  "write_commands_implemented": False,
  "forbidden_command_opcodes": {},
  "wall_clock_rate_claimed": False,
  "control_timing": {"requests": [], "rtt_statistics": None},
  "capture_window": {},
  "message": "",
}

# Audited inert ephemeral scheduler canary. This is the only live ephemeral-runtime
# operation exposed by TSK; no steering bridge binary or bridge endpoint exists.
ephemeral_lock = threading.Lock()
ephemeral_state = {
  "status": "idle",   # idle | running | passed | failed
  "step": "",
  "message": "",
  "f181": "",
  "package": {},
  "result": {},
  "bridge_execution_exposed": False,
}

# EPS identity + observation-oriented service-surface map.
ident_lock = threading.Lock()
ident_state = {
  "status": "idle",   # idle | running | mapped | unreachable | failed
  "count": 0,
  "last": "",
  "panda": "",
  "eps_bus": -1,
  "eps_rx_bus": -1,
  "eps_tx": "",
  "eps_rx": "",
  "identity": [],
  "services": [],
  "message": "",
}

# Reset-window probe — hard reset, then hammer PROGRAMMING through the reboot.
reset_lock = threading.Lock()
reset_state = {
  "status": "idle",   # idle | running | entered | blocked | unreachable | failed
  "count": 0,
  "last": "",
  "panda": "",
  "eps_bus": -1,
  "reset": "",
  "attempts": [],
  "session_after": "",
  "message": "",
}

# Level 0x03 seed isolation probe — seed-only (no key sent), safe to re-run.
level3_lock = threading.Lock()
level3_state = {
  "status": "idle",   # idle | running | reproduced | conditional | no_seed | unreachable | failed
  "count": 0,
  "last": "",
  "panda": "",
  "eps_bus": -1,
  "tests": [],
  "seeds": [],
  "primer": "",
  "message": "",
}

# Application 0x03/0x04 comparison — exact Sienna secret; cross-calibration SEND_KEY
# is explicitly armed because a wrong key is a counted attempt.
sendkey_lock = threading.Lock()
sendkey_state = {
  "status": "idle",   # idle | running | armed_required | unlocked | invalid_key | locked | denied | rejected | no_seed | unreachable | failed
  "last": "",
  "panda": "",
  "eps_bus": -1,
  "session": "",
  "seed": "",
  "key": "",
  "send_key": "",
  "post_unlock_reads": [],
  "target_f181": "",
  "target_f181_hex": "",
  "cross_calibration": False,
  "armed": False,
  "message": "",
}

# Pre-programming preamble probe — lock read + exploit-surface refusal codes + the 0x85/0x28
# preamble variants + a DTC diff. No key sent, no attempt counter touched.
preamble_lock = threading.Lock()
preamble_state = {
  "status": "idle",   # idle | running | security_open | programming_open | locked | blocked | dropped_out | unreachable | failed
  "count": 0,
  "last": "",
  "panda": "",
  "eps_bus": -1,
  "identity": [],
  "lock": {},
  "services": [],
  "variants": [],
  "dtc": {},
  "reads": [],
  "liveness": "",
  "message": "",
}

# Exhaustive UDS sweep (Not Ready to Drive) — every service byte, every sub-function,
# deadline-bounded and resumable across runs.
sweep_lock = threading.Lock()
sweep_state = {
  "status": "idle",   # idle | running | complete | partial | unreachable | failed
  "count": 0,
  "last": "",
  "stage": "",
  "panda": "",
  "eps_tx": "",
  "eps_bus": -1,
  "eps_rx_bus": -1,
  "eps_rx": "",
  "timeout_ms": 0,
  "stages": [],
  "answering": [],
  "silent": [],
  "responders": [],
  "responder_routes": [],
  "records": 0,
  "frontier": "",
  "hypotheses": [],
  "message": "",
}

# READY passive capture. This state never includes diagnostic transmission.
ready_lock = threading.Lock()
ready_state = {
  "status": "idle",   # idle | running | captured | failed
  "count": 0,
  "last": "",
  "stage": "",
  "mode": "passive",
  "run_id": "",
  "panda": "",
  "eps_bus": -1,
  "capture": {},
  "diff": [],
  "responders": [],
  "cross": [],
  "seeds": [],
  "frames": 0,
  "tx_echoes_filtered": 0,
  "path": "",
  "message": "",
}

# READY active diff. It is a separate operation and only replays requests recovered
# from the prior Not Ready to Drive transcript.
ready_diff_lock = threading.Lock()
ready_diff_state = {
  "status": "idle",   # idle | running | complete | no_sweep | unreachable | failed
  "count": 0,
  "last": "",
  "stage": "",
  "mode": "active_diff",
  "run_id": "",
  "panda": "",
  "eps_tx": "",
  "eps_bus": -1,
  "eps_rx_bus": -1,
  "eps_rx": "",
  "diff": [],
  "frames": 0,
  "path": "",
  "message": "",
}


def _route_metadata(result: dict) -> dict:
  """Preserve physical-route dimensions that a logical Panda bus number omits."""
  keys = ("elm327_param", "semantic_path", "alternate_routes")
  return {key: result[key] for key in keys if key in result}


def operation_states_snapshot() -> dict:
  """Copy current job states into the evidence manifest without holding locks during I/O."""
  snapshots = {}
  for name, lock, state in (
      ("can", can_lock, can_state), ("dataflash", df_lock, df_state),
      ("sniff", sniff_lock, sniff_state), ("dataflash_diag", diag_lock, diag_state),
      ("programming", probe_lock, probe_state), ("read_memory", readmem_lock, readmem_state),
      ("xcp_observer", xcp_lock, xcp_state),
      ("ephemeral_canary", ephemeral_lock, ephemeral_state),
      ("identity", ident_lock, ident_state), ("reset", reset_lock, reset_state),
      ("level3", level3_lock, level3_state), ("send_key", sendkey_lock, sendkey_state),
      ("preamble", preamble_lock, preamble_state), ("uds_sweep", sweep_lock, sweep_state),
      ("ready_passive", ready_lock, ready_state),
      ("ready_active_diff", ready_diff_lock, ready_diff_state)):
    with lock:
      snapshots[name] = dict(state)
  return snapshots


def _identity_value(identity: list[dict], name: str) -> str:
  for entry in identity:
    if entry.get("name") == name and entry.get("hex"):
      return str(entry.get("ascii", "")).strip(".\x00 ")
  return ""


def ram_exec_geometry_status(identity: list[dict], *, fixture_sha256: str = DATAFLASH_PAYLOAD_SHA256) -> dict:
  """Return independent boot geometry, bootstrap-family, and fixture gates."""
  app_sw = _identity_value(identity, "app_sw_id")
  geometry = known_ram_exec_geometry(app_sw) if app_sw else None
  bootstrap = public_bootstrap_status(app_sw, fixture_sha256=fixture_sha256) if app_sw else {
    "compatible": False, "fixture_evidenced": False, "f181": "", "message": "EPS F181 is not identified."
  }
  if geometry is None:
    return {
      "ready": False,
      "f181": app_sw,
      "geometry": None,
      "bootstrap": bootstrap,
      "dataflash_fixture_ready": bool(bootstrap.get("fixture_evidenced")),
      "message": (
        "No authenticated RequestDownload/0x10F0/callback geometry is evidenced for this exact F181. " +
        "A successful PROGRAMMING handoff or an observed linker VMA is not sufficient evidence."
      ),
    }
  return {
    "ready": True,
    "f181": app_sw,
    "geometry": geometry.public_dict(),
    "bootstrap": bootstrap,
    "dataflash_fixture_ready": bool(bootstrap.get("fixture_evidenced")),
    "message": (
      "Exact F181 has evidenced authenticated RAM-exec geometry and selected DataFlash fixture."
      if bootstrap.get("fixture_evidenced") else
      "Exact F181 has evidenced boot geometry, but selected DataFlash ciphertext is not target-evidenced."
    ),
  }


def persist_verified_recovery(key: str, verification: dict, *, source: str) -> tuple[dict, dict]:
  """Persist a verified key privately and refresh its evidence-bound target profile."""
  recovered = persist_recovered_key(key, verification, source=source)
  with ident_lock:
    identity_snapshot = dict(ident_state)
    identity_snapshot["identity"] = [dict(row) for row in ident_state.get("identity", [])]
  profile = persist_target_profile(identity_snapshot, verification=verification,
                                   oracle_path=can_oracle_path())
  return recovered, profile


def dashboard_payload() -> dict:
  """Project raw TSK state into the evidence-gated recovery/integration workflow."""
  snapshots = operation_states_snapshot()
  identity = snapshots["identity"]
  can = snapshots["can"]
  dataflash = snapshots["dataflash"]
  programming = snapshots["programming"]
  key = RebootManager.key_status_payload()
  installed = bool(key.get("installed"))
  recovered = public_recovered_key_status()
  profile = public_target_profile_status()
  readiness = profile.get("readiness", {})

  app_sw = _identity_value(identity.get("identity", []), "app_sw_id")
  spare_part = _identity_value(identity.get("identity", []), "spare_part_no")
  ecu_serial = _identity_value(identity.get("identity", []), "ecu_serial")
  identity_ready = identity.get("status") == "mapped" and bool(app_sw)
  ram_geometry = ram_exec_geometry_status(identity.get("identity", []))
  ram_geometry_ready = bool(ram_geometry["ready"])
  bootstrap_ready = bool(ram_geometry.get("bootstrap", {}).get("compatible"))
  dataflash_fixture_ready = bool(ram_geometry.get("dataflash_fixture_ready"))
  legacy_ram_fixture_ready = bool(app_sw and fixture_is_evidenced(app_sw, RAM_DUMP_FIXTURE_SHA256) and
                                  any(normalize_f181(raw) == app_sw for raw in TSKExtractor.APPLICATION_VERSIONS))
  runtime = public_runtime_status(app_sw) if app_sw else public_runtime_status("")
  known_transfer = bool(ram_geometry_ready and ram_geometry["geometry"].get("programming_handoff_verified"))
  can_ready = bool(can.get("ready") or can.get("status") == "complete")
  key_recovered = bool(recovered.get("recovered"))
  integration_ready = bool(readiness.get("openpilot_integration_reviewed"))
  code_ready = bool(readiness.get("openpilot_code_ready"))
  stationary_ready = bool(readiness.get("stationary_acceptance_verified"))
  operational_profile_ready = bool(readiness.get("operational_install_allowed"))
  programming_status = str(programming.get("status", "idle"))
  programming_ready = known_transfer or programming_status == "entered"
  programming_blocked = programming_status in ("failed", "rejected", "blocked", "unreachable")
  dataflash_ready = bool(dataflash.get("ready") or dataflash.get("status") == "partial")

  exact_f33 = app_sw == CAMRY_F33_PRIMARY_SW
  # The full evidence checkpoint carries tuple-keyed tables that are not JSON-safe;
  # expose only the dashboard-relevant projection.
  f33_status = (
    {key: value for key, value in public_camry_f33_status().items()
     if key in ("secondary_software_id", "checkpoint", "production_architecture",
                "remaining_production_gates", "production_output_allowed")}
    if exact_f33 else None
  )
  route = {
    "tx": identity.get("eps_tx", ""),
    "rx": identity.get("eps_rx", ""),
    "tx_bus": identity.get("eps_bus", -1),
    "rx_bus": identity.get("eps_rx_bus", -1),
    "elm327_param": identity.get("elm327_param", -1),
    "semantic_path": identity.get("semantic_path", ""),
    "alternate_routes": identity.get("alternate_routes", []),
  }
  route_ready = identity_ready and route["tx_bus"] >= 0 and bool(route["tx"] and route["rx"])

  if installed and operational_profile_ready:
    stage = "complete"
    next_action = {
      "id": "complete", "title": "Integration verified",
      "description": "The recovered key is bound to a reviewed target profile, stationary verification passed, and SecOCKey is installed.",
      "href": "/api/evidence-bundle", "label": "Download evidence", "vehicle_state": "Any", "tone": "success",
    }
  elif not identity_ready:
    stage = "identify"
    next_action = {
      "id": "identify", "title": "Identify the EPS",
      "description": "Read F181 and establish the complete diagnostic route before any recovery attempt.",
      "href": "/ident-map.html", "label": "Identify EPS", "vehicle_state": "Not Ready to Drive", "tone": "primary",
    }
  elif not can_ready:
    stage = "capture_can"
    next_action = {
      "id": "capture_can", "title": "Discover the target SecOC surface",
      "description": (
        "Capture the full READY-state bus window. Known Toyota IDs are annotations; " +
        "unknown classic SecOC streams are discovered structurally and later proven cryptographically."
      ),
      "href": "/can-collector.html", "label": "Capture CAN evidence", "vehicle_state": "READY", "tone": "primary",
    }
  elif not key_recovered and not programming_ready:
    stage = "programming"
    if programming_blocked:
      next_action = {
        "id": "programming", "title": "Programming handoff is blocked",
        "description": programming.get("message") or "The EPS did not reach its bootloader on the preserved physical route.",
        "href": "", "label": "Open programming diagnostics", "vehicle_state": "Not Ready to Drive",
        "tone": "warning", "action": "research",
      }
    else:
      next_action = {
        "id": "programming", "title": "Confirm the programming handoff",
        "description": "Unknown calibration: confirm bootloader reappearance on the preserved route before sending a dump payload.",
        "href": "/prog-probe.html", "label": "Run handoff probe", "vehicle_state": "Not Ready to Drive", "tone": "primary",
      }
  elif not key_recovered and not ram_geometry_ready:
    stage = "ram_geometry"
    next_action = {
      "id": "ram_geometry", "title": "Establish authenticated RAM-exec geometry",
      "description": (
        "The EPS can reach its bootloader, but this exact F181 has no verified RequestDownload/0x10F0/callback geometry. " +
        "Do not reuse FEBF0000 or a reported linker VMA until the authenticated payload contract is independently established."
      ),
      "href": "", "label": "RAM-exec geometry required", "vehicle_state": "Research / bench",
      "tone": "warning", "action": "research",
    }
  elif not key_recovered and not dataflash_fixture_ready and not legacy_ram_fixture_ready:
    stage = "bootstrap_fixture"
    next_action = {
      "id": "bootstrap_fixture", "title": "Establish the exact bootstrap payload",
      "description": (
        "This EPS is in an evidenced authenticated-RAM bootstrap family, but the selected 4 KiB DataFlash " +
        "ciphertext is not evidenced byte-for-byte for this F181. Do not infer fixture acceptance from shared RAM geometry."
      ),
      "href": "/ephemeral-runtime.html", "label": "Review runtime/bootstrap evidence",
      "vehicle_state": "Research / bench", "tone": "warning", "action": "research",
    }
  elif not key_recovered and not dataflash_ready:
    stage = "dataflash"
    if legacy_ram_fixture_ready and not dataflash_fixture_ready:
      next_action = {
        "id": "dataflash", "title": "Recover key material with the known RAM extractor",
        "description": (
          "The public RAM payload is target-evidenced for this legacy key-table calibration; the separate DataFlash " +
          "ciphertext is not. Use the calibration-specific RAM extractor rather than projecting DataFlash fixture acceptance."
        ),
        "href": "/extractor.html", "label": "Run RAM extractor", "vehicle_state": "Not Ready to Drive", "tone": "primary",
      }
    else:
      next_action = {
        "id": "dataflash", "title": "Recover key material",
        "description": (
          "Dump EPS DataFlash using the exact F181's evidenced boot geometry and target-evidenced encrypted fixture. " +
          "A recovered candidate becomes trusted only after it authenticates captured target traffic."
        ),
        "href": "/dataflash-collector.html", "label": "Dump DataFlash", "vehicle_state": "Not Ready to Drive", "tone": "primary",
      }
  elif not key_recovered:
    stage = "verify"
    next_action = {
      "id": "verify", "title": "Recover and verify the target key",
      "description": (
        "Scan every eligible DataFlash window and cryptographically classify it against the discovered target SecOC streams. " +
        "This does not install SecOCKey."
      ),
      "href": "", "label": "Find & verify key", "vehicle_state": "Any", "tone": "primary", "action": "match",
    }
  elif not profile.get("present") or not integration_ready:
    stage = "integration"
    next_action = {
      "id": "integration", "title": "Complete the target integration profile",
      "description": (
        "The key is recovered. Pin the target DBC, safety flags, steering mode, EPS scale, command/status roles, " +
        "and longitudinal topology before openpilot can use it."
      ),
      "href": "/target-profile.html", "label": "Review target profile", "vehicle_state": "Any", "tone": "primary",
    }
  elif not code_ready:
    stage = "implementation"
    next_action = {
      "id": "implementation", "title": "Implement and audit the target in opendbc",
      "description": (
        "The reviewed manifest is complete, but the checked-out opendbc must contain this exact platform and EPS F181 and agree on " +
        "DBC, steering mode, EPS scale, longitudinal ownership, and panda safetyParam."
      ),
      "href": "/target-profile.html", "label": "Review implementation audit", "vehicle_state": "Any", "tone": "primary",
    }
  elif not stationary_ready:
    stage = "stationary"
    next_action = {
      "id": "stationary", "title": "Run stationary acceptance verification",
      "description": "Verify the reviewed profile against the stationary/bench target and its status feedback before allowing operational key installation.",
      "href": "/stationary-verify.html", "label": "Stationary verification", "vehicle_state": "Stationary / bench", "tone": "primary",
    }
  elif not installed:
    stage = "install"
    next_action = {
      "id": "install", "title": "Install the verified target key",
      "description": "All profile and stationary gates have passed. Install the already recovered key into the existing SecOCKey interface.",
      "href": "", "label": "Install verified key", "vehicle_state": "Any", "tone": "primary", "action": "install-key",
    }
  else:
    # A key installed by an older TSK build must not be mistaken for evidence that
    # today's profile gates passed.
    stage = "integration"
    next_action = {
      "id": "integration", "title": "Reconcile the existing SecOCKey",
      "description": (
        "A SecOCKey is present, but no complete evidence-bound target profile proves it is safe for this integration. " +
        "Continue profile verification."
      ),
      "href": "/target-profile.html", "label": "Review target profile", "vehicle_state": "Any", "tone": "warning",
    }

  if exact_f33:
    stage = "f33_stock_b6_capture"
    next_action = {
      "id": stage,
      "title": "Capture stock B6 off → active → off",
      "description": (
        "Use full 60-second windows to retain exact-F33 0x0B6/PDU44 traffic across stock LTA transitions. " +
        "Close the 28-byte application template, sequence restart, freshness, and 0x351/0x394/0x4A3 status evidence; " +
        "this is lateral bring-up evidence, not CPU-visible key recovery."
      ),
      "href": "/can-collector.html",
      "label": "Capture F33 CAN evidence",
      "vehicle_state": "READY · relay pass-through",
      "tone": "primary",
    }

  def step_state(done: bool, step_id: str) -> str:
    if done:
      return "complete"
    return "current" if stage == step_id else "pending"

  profile_streams = can.get("profile_discovery", {}).get("streams", [])
  included_streams = [row for row in profile_streams if row.get("scan_included")]
  if exact_f33:
    assert f33_status is not None
    gate_titles = (
      "Stock B6 capture",
      "Relay authority",
      "ICU-S generation",
      "Override and current policy",
      "Live status transitions",
      "Volatile runtime pivot",
    )
    steps = [
      {
        "id": f"f33_gate_{index + 1}",
        "title": title,
        "state": "current" if index == 0 else "pending",
        "detail": gate,
      }
      for index, (title, gate) in enumerate(zip(
        gate_titles, f33_status["remaining_production_gates"], strict=True,
      ))
    ]
  else:
    steps = [
      {"id": "identify", "title": "Identify EPS", "state": step_state(identity_ready, "identify"),
       "detail": app_sw or "Read F181 and diagnostic route"},
      {"id": "capture_can", "title": "Discover SecOC surface", "state": step_state(can_ready, "capture_can"),
       "detail": (f"{can.get('sync_count', 0)} sync · {len(included_streams)} candidate stream(s)" if can_ready else
                  f"{can.get('sync_count', 0)} sync · capture incomplete")},
      {"id": "programming", "title": "Confirm recovery route", "state": step_state(key_recovered or programming_ready, "programming"),
       "detail": ("Key already recovered" if key_recovered else "Known transfer path" if known_transfer else
                  "Bootloader reappeared" if programming_status == "entered" else "Required if DataFlash recovery is needed")},
      {"id": "ram_geometry", "title": "Verify boot RAM-exec geometry", "state": step_state(key_recovered or ram_geometry_ready, "ram_geometry"),
       "detail": ("Key already recovered" if key_recovered else
                  f"{ram_geometry['geometry']['load_addr']} / {ram_geometry['geometry']['size']} evidenced for F181" if ram_geometry_ready else
                  "Authenticated RequestDownload/0x10F0/callback geometry not established")},
      {"id": "bootstrap_fixture", "title": "Verify exact bootstrap fixture",
       "state": step_state(key_recovered or dataflash_fixture_ready or legacy_ram_fixture_ready, "bootstrap_fixture"),
       "detail": ("Key already recovered" if key_recovered else "DataFlash fixture target-evidenced" if dataflash_fixture_ready else
                  "RAM extractor fixture target-evidenced" if legacy_ram_fixture_ready else
                  "Bootstrap family known; exact ciphertext still required")},
      {"id": "dataflash", "title": "Recover key material", "state": step_state(key_recovered or dataflash_ready, "dataflash"),
       "detail": ("Key material recovered" if key_recovered else "Complete DataFlash dump" if dataflash.get("ready") else
                  "Usable partial dump" if dataflash.get("status") == "partial" else
                  "Blocked on boot RAM-exec geometry" if not ram_geometry_ready else
                  "Blocked on exact bootstrap fixture" if not (dataflash_fixture_ready or legacy_ram_fixture_ready) else "Waiting")},
      {"id": "verify", "title": "Cryptographically recover key", "state": step_state(key_recovered, "verify"),
       "detail": (f"Recovered key {recovered.get('key_sha256_prefix', '')}" if key_recovered else "No operational install at this step")},
      {"id": "integration", "title": "Review target integration", "state": step_state(integration_ready, "integration"),
       "detail": "Reviewed target-specific DBC/safety/control profile" if integration_ready else "Target-specific fields still required"},
      {"id": "implementation", "title": "Audit opendbc implementation", "state": step_state(code_ready, "implementation"),
       "detail": "Exact target/F181 and reviewed parameters agree with source" if code_ready else "No source-verified target implementation yet"},
      {"id": "stationary", "title": "Stationary verification", "state": step_state(stationary_ready, "stationary"),
       "detail": "Profile-bound acceptance passed" if stationary_ready else "Not yet proven on target"},
      {"id": "install", "title": "Install operational key", "state": step_state(installed and operational_profile_ready, "install"),
       "detail": "Installed after all gates" if installed and operational_profile_ready else
                 "Existing unverified install" if installed else "Blocked until all gates pass"},
    ]

  failures = []
  for name, snapshot in (("CAN capture", can), ("DataFlash dump", dataflash), ("Programming handoff", programming)):
    if snapshot.get("status") in ("failed", "rejected", "blocked", "unreachable", "unusable_partial"):
      failures.append({"name": name, "status": snapshot.get("status"), "message": snapshot.get("message", "")})

  return {
    "target": {
      "kind": "camry_f33" if exact_f33 else "generic",
      "exact": exact_f33,
      "label": "2026 Camry / F33" if exact_f33 else (app_sw or "Unidentified Toyota EPS"),
      "status": f33_status,
    },
    "key": key,
    "recovered_key": recovered,
    "target_profile": profile,
    "vehicle": {
      "identified": identity_ready,
      "known_transfer": known_transfer,
      "ram_exec_geometry": ram_geometry,
      "bootstrap_compatible": bootstrap_ready,
      "dataflash_fixture_ready": dataflash_fixture_ready,
      "ephemeral_runtime": runtime,
      "app_sw_id": app_sw,
      "spare_part_no": spare_part,
      "ecu_serial": ecu_serial,
      "panda": identity.get("panda", ""),
    },
    "route": {**route, "identified": route_ready},
    "recovery": {"stage": stage, "next_action": next_action, "steps": steps, "failures": failures},
    "can": can,
    "dataflash": dataflash,
    "programming": programming,
    "reboot": get_reboot_actions_payload(),
  }

def _df_progress(status=None, frames=None, bytes_done=None, total=None, message=None) -> None:
  with df_lock:
    if status is not None:
      df_state["status"] = status
    if frames is not None:
      df_state["frames"] = frames
    if bytes_done is not None:
      df_state["bytes"] = bytes_done
    if total is not None:
      df_state["total"] = total
    if message is not None:
      df_state["message"] = message


def _run_dataflash_mock() -> None:
  # Laptop dry run: ramp progress over a couple of seconds so the collector page
  # shows movement, then land on complete. The partial/unusable_partial paths only happen
  # on a real device.
  for done in (4096, 8192, 16384, 24576, DUMP_TOTAL):
    time.sleep(0.4)
    _df_progress(status="running", frames=done // 4, bytes_done=done, total=DUMP_TOTAL)
  with df_lock:
    df_state.update(status="complete", frames=DUMP_TOTAL // 4, bytes=DUMP_TOTAL,
                    total=DUMP_TOTAL, size=DUMP_TOTAL, ready=True,
                    message=f"Dump complete: {DUMP_TOTAL} bytes (mock).")


def _run_dataflash_job(use_recovery_payload: bool = False) -> None:
  try:
    result = dump_dataflash(progress_cb=_df_progress, auto_reset=use_recovery_payload)
    status = result.get("status", "failed")
    with df_lock:
      df_state.update(
        status=status,
        frames=result.get("frames", df_state["frames"]),
        bytes=result.get("bytes", df_state["bytes"]),
        total=result.get("total", DUMP_TOTAL),
        message=result.get("message", ""),
        ready=(status == "complete"),
        size=result.get("bytes", 0) if status == "complete" else 0,
        payload_variant=result.get("payload_variant", "standard"),
        coverage_path=result.get("coverage_path", ""),
        longest_covered_run=result.get("longest_covered_run", 0),
        known_key_window_covered=result.get("known_key_window_covered", False),
        application_f181=result.get("application_f181", ""),
        ram_exec_geometry=result.get("ram_exec_geometry", {}),
        route=result.get("route", {}),
        programming_handoff=result.get("programming_handoff", {}),
      )
  except NotAGNOSError:
    _run_dataflash_mock()
  except Exception as e:
    with df_lock:
      df_state.update(status="failed", message=str(e), ready=False, size=0)
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_dataflash_job(*, use_recovery_payload: bool = False) -> bool:
  # panda_lock is the gate: a running extract/dump/collect holds it, so a
  # concurrent dump is rejected here. The job thread releases it in its finally.
  if not panda_lock.acquire(blocking=False):
    return False
  with df_lock:
    df_state.update(status="running", frames=0, bytes=0, total=DUMP_TOTAL,
                    message="", ready=False, size=0,
                    payload_variant="auto-reset-experimental" if use_recovery_payload else "standard",
                    coverage_path="", longest_covered_run=0, known_key_window_covered=False,
                    application_f181="", ram_exec_geometry={}, route={}, programming_handoff={})
  try:
    threading.Thread(target=_run_dataflash_job, args=(use_recovery_payload,), name="tsk_dataflash_dump", daemon=True).start()
  except Exception:
    # The job thread never took ownership, so release the lock and clear the state
    # here — otherwise panda_lock would wedge every panda op until a restart.
    with df_lock:
      df_state.update(status="failed", message="Could not start the dump job.", ready=False)
    panda_lock.release()
    return False
  return True


def clear_dataflash() -> bool:
  # Refuse while a dump is in flight: a completing dump would otherwise re-set the
  # state and re-write the file this clear just removed. Returns False if running.
  with df_lock:
    if df_state["status"] == "running":
      return False
    df_state.update(ready=False, status="idle", frames=0, bytes=0,
                    total=DUMP_TOTAL, message="", size=0, payload_variant="standard",
                    coverage_path="", longest_covered_run=0, known_key_window_covered=False,
                    application_f181="", ram_exec_geometry={}, route={}, programming_handoff={})
  for path in (dump_path(), partial_dump_path(), partial_coverage_path()):
    try:
      path.unlink()
    except FileNotFoundError:
      pass
    except OSError:
      pass
  return True


def rehydrate_dataflash_state() -> None:
  # A completed dump persists on disk; reflect it after a restart so a finished
  # dump doesn't show as not-done and prompt a needless re-dump. A complete dump
  # is exactly DUMP_TOTAL bytes, so a truncated file can't masquerade as done.
  try:
    size = dump_path().stat().st_size
  except OSError:
    size = None
  if size == DUMP_TOTAL:
    with df_lock:
      df_state.update(ready=True, status="complete", frames=DUMP_TOTAL // 4,
                      bytes=DUMP_TOTAL, total=DUMP_TOTAL, size=DUMP_TOTAL,
                      message="Dump complete.")
    return
  # No complete dump, but a .partial sidecar means candidate-sized coverage was
  # retained. Reflect it as partial so Find stays enabled after a restart; new
  # partials also carry a byte-coverage map used by the matcher.
  try:
    partial_size = partial_dump_path().stat().st_size
  except OSError:
    return
  try:
    coverage_known = partial_coverage_path().stat().st_size == DUMP_TOTAL
  except OSError:
    coverage_known = False
  with df_lock:
    df_state.update(ready=False, status="partial", total=DUMP_TOTAL, size=partial_size,
                    message=("Partial dump on disk with byte coverage map.\n" if coverage_known else
                             "Legacy partial dump on disk without a coverage map.\n") +
                            "Try the Find Toyota Security Key button; only cryptographically verified candidates are trusted.")


def _can_progress(seconds=None, sync=None, protected=None) -> None:
  with can_lock:
    if seconds is not None:
      can_state["seconds"] = seconds
    if sync is not None:
      can_state["sync_count"] = sync
    if protected is not None:
      can_state["protected_count"] = protected


def _run_can_mock() -> None:
  # Laptop dry run: ramp counts over a couple of seconds, then land on complete.
  for i in range(1, 7):
    time.sleep(0.4)
    _can_progress(seconds=i * 10.0, sync=i * 10, protected=i * 600)
  with can_lock:
    can_state.update(status="complete", ready=True, seconds=60.0,
                     sync_count=60, protected_count=3600,
                     protected_by_id={"0x131": 1200, "0x183": 1200, "0x2e4": 1200},
                     counts_by_bus={1: {"sync": 60, "protected": 3600}},
                     legacy_lateral_observed=True, legacy_lateral_counts={"0x131": 1200, "0x2e4": 1200},
                     legacy_longitudinal_observed=True, legacy_longitudinal_counts={"0x183": 1200},
                     profile_discovery={"streams": [
                       {"bus": 1, "addr": "0x131", "addr_int": 0x131, "samples": 1200, "lengths": [8], "scan_included": True},
                       {"bus": 1, "addr": "0x183", "addr_int": 0x183, "samples": 1200, "lengths": [8], "scan_included": True},
                       {"bus": 1, "addr": "0x2e4", "addr_int": 0x2E4, "samples": 1200, "lengths": [8], "scan_included": True},
                     ], "unknown_structural_candidates": 0, "unknown_scan_streams": 0, "scan_included_samples": 3600},
                     elm327_param=1, semantic_path="normal-harness",
                     message="Collected target-profile CAN evidence (mock).")


def _run_can_job() -> None:
  try:
    result = collect_can(progress_cb=_can_progress)
    status = result.get("status", "failed")
    with can_lock:
      can_state.update(
        status=status,
        sync_count=result.get("sync", can_state["sync_count"]),
        protected_count=result.get("protected", can_state["protected_count"]),
        protected_by_id=result.get("protected_by_id", {}),
        counts_by_bus=result.get("counts_by_bus", {}),
        legacy_lateral_observed=result.get("legacy_lateral_observed", False),
        legacy_lateral_counts=result.get("legacy_lateral_counts", {}),
        legacy_longitudinal_observed=result.get("legacy_longitudinal_observed", False),
        legacy_longitudinal_counts=result.get("legacy_longitudinal_counts", {}),
        profile_discovery=result.get("profile_discovery", {}),
        message=result.get("message", ""),
        ready=(status == "complete"),
        **_route_metadata(result),
      )
    if status == "complete" and public_recovered_key_status().get("recovered"):
      try:
        with ident_lock:
          identity_snapshot = dict(ident_state)
          identity_snapshot["identity"] = [dict(row) for row in ident_state.get("identity", [])]
        refresh_target_profile_from_recovered(identity_snapshot, oracle_path=can_oracle_path())
      except Exception as profile_error:
        with can_lock:
          can_state["message"] = (can_state.get("message", "") +
                                  f" Profile refresh failed: {profile_error}").strip()
  except NotAGNOSError:
    _run_can_mock()
  except Exception as e:
    with can_lock:
      can_state.update(status="failed", message=str(e), ready=False)
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_can_job() -> bool:
  # panda_lock is the gate: a running extract/dump/collect holds it, so a
  # concurrent collect is rejected here. The job thread releases it in its finally.
  if not panda_lock.acquire(blocking=False):
    return False
  with can_lock:
    can_state.update(status="running", sync_count=0, protected_count=0,
                     protected_by_id={}, counts_by_bus={},
                     legacy_lateral_observed=False, legacy_lateral_counts={},
                     legacy_longitudinal_observed=False, legacy_longitudinal_counts={},
                     profile_discovery={},
                     seconds=0.0, message="", ready=False, elm327_param=-1, semantic_path="")
  try:
    threading.Thread(target=_run_can_job, name="tsk_can_collect", daemon=True).start()
  except Exception:
    # Same as the dump: release the lock and clear the state if the thread that
    # would release it never starts.
    with can_lock:
      can_state.update(status="failed", message="Could not start the collection job.", ready=False)
    panda_lock.release()
    return False
  return True


def clear_can() -> bool:
  # Refuse while a collection is in flight so a finishing job can't resurrect the
  # oracle this clear just removed. Returns False if running.
  with can_lock:
    if can_state["status"] == "running":
      return False
    can_state.update(ready=False, status="idle", sync_count=0,
                     protected_count=0, protected_by_id={}, counts_by_bus={},
                     legacy_lateral_observed=False, legacy_lateral_counts={},
                     legacy_longitudinal_observed=False, legacy_longitudinal_counts={},
                     profile_discovery={},
                     seconds=0.0, elm327_param=-1, semantic_path="", message="")
  try:
    can_oracle_path().unlink()
  except FileNotFoundError:
    pass
  except OSError:
    pass
  return True


def rehydrate_can_state() -> None:
  # Re-run the generalized structural discovery over persisted evidence after a
  # restart; do not collapse the profile back to the legacy 0x131/0x2E4 gate.
  sync, protected = count_oracle_frames()
  try:
    analysis = load_oracle_discovery(can_oracle_path())
  except OSError:
    return
  streams = analysis["streams"]
  included = [row for row in streams if row["scan_included"]]
  included_samples = sum(int(row["samples"]) for row in included)
  by_addr = {int(row["addr_int"]): int(row["samples"]) for row in streams}
  lateral_counts = {f"0x{addr:03x}": by_addr.get(addr, 0)
                    for addr in sorted(CURRENT_OPENPILOT_LATERAL_PROTECTED_ADDRS)}
  longitudinal_counts = {f"0x{addr:03x}": by_addr.get(addr, 0)
                         for addr in sorted(CURRENT_OPENPILOT_LONGITUDINAL_PROTECTED_ADDRS)}
  lateral_observed = all(value >= 2 for value in lateral_counts.values())
  longitudinal_observed = all(value >= 2 for value in longitudinal_counts.values())
  ready = len(analysis["sync_samples"]) >= SYNC_TARGET and included_samples >= PROTECTED_TARGET
  with can_lock:
    can_state.update(
      ready=ready,
      status="complete" if ready else "insufficient",
      sync_count=sync,
      protected_count=protected,
      legacy_lateral_observed=lateral_observed,
      legacy_lateral_counts=lateral_counts,
      legacy_longitudinal_observed=longitudinal_observed,
      legacy_longitudinal_counts=longitudinal_counts,
      profile_discovery={
        "streams": streams,
        "can_inventory": analysis["can_inventory"],
        "unknown_structural_candidates": analysis["unknown_structural_candidates"],
        "unknown_scan_streams": analysis["unknown_scan_streams"],
        "scan_included_samples": included_samples,
      },
      message=(f"Persisted target-profile evidence: {len(analysis['sync_samples'])} sync samples, " +
               f"{included_samples} cryptographically eligible protected samples across {len(included)} stream(s)."),
    )


def _sniff_progress(seconds=None, frames=None, buses=None) -> None:
  with sniff_lock:
    if seconds is not None:
      sniff_state["seconds"] = seconds
    if frames is not None:
      sniff_state["frames"] = frames
    if buses is not None:
      sniff_state["bus_count"] = buses


def _run_sniff_mock() -> None:
  # Laptop dry run: ramp progress, then land on a plausible bus map (bus 0 carrying
  # the SecOC markers, bus 1 with unrelated traffic, bus 2 silent) so the page
  # layout is exercised. summarize_counts keeps the shape identical to the real run.
  from collections import Counter
  for i in range(1, 5):
    time.sleep(0.4)
    _sniff_progress(seconds=i * 2.0, frames=i * 260, buses=2)
  demo = {
    0: Counter({0x0f: 30, 0x2e4: 50, 0x131: 40, 0x344: 20, 0x25: 120, 0xaa: 120}),
    1: Counter({0x3bc: 12, 0x1c4: 12}),
  }
  demo_maxlen = {0: 8, 1: 64}   # bus 1 carrying CAN-FD frames, to exercise the FD display
  result = summarize_counts(demo, 8.0, demo_maxlen)
  with sniff_lock:
    sniff_state.update(status="complete", seconds=result["seconds"], frames=result["total"],
                       total=result["total"], buses=result["buses"], markers=result["markers"],
                       fd_buses=result["fd_buses"], message=result["message"] + " (mock)")


def _run_sniff_job() -> None:
  try:
    result = sniff_can(progress_cb=_sniff_progress)
    with sniff_lock:
      sniff_state.update(
        status=result.get("status", "failed"),
        seconds=result.get("seconds", 0.0),
        frames=result.get("total", 0),
        total=result.get("total", 0),
        buses=result.get("buses", []),
        markers=result.get("markers", []),
        fd_buses=result.get("fd_buses", []),
        message=result.get("message", ""),
        **_route_metadata(result),
      )
  except NotAGNOSError:
    _run_sniff_mock()
  except Exception as e:
    with sniff_lock:
      sniff_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_sniff_job() -> bool:
  # panda_lock is the gate: a running extract/dump/collect holds it, so a
  # concurrent sniff is rejected here. The job thread releases it in its finally.
  if not panda_lock.acquire(blocking=False):
    return False
  with sniff_lock:
    sniff_state.update(status="running", seconds=0.0, frames=0, bus_count=0,
                       total=0, buses=[], markers=[], message="")
  try:
    threading.Thread(target=_run_sniff_job, name="tsk_can_sniff", daemon=True).start()
  except Exception:
    # Same as the other jobs: release the lock and clear state if the thread that
    # would release it never starts.
    with sniff_lock:
      sniff_state.update(status="failed", message="Could not start the sniff job.")
    panda_lock.release()
    return False
  return True


def _diag_progress(steps=None, last=None) -> None:
  with diag_lock:
    if steps is not None:
      diag_state["step_count"] = steps
    if last is not None:
      diag_state["last"] = last


def _run_diag_mock(allow_cross_calibration_send_key: bool = False) -> None:
  # Laptop dry run models the useful unknown-calibration boundary: PROGRAMMING and the
  # bootloader seed are observed automatically. A counted bootloader SEND_KEY happens
  # only when explicitly armed, and unknown RAM geometry still blocks payload writes.
  names = ["connect panda", "identity", "PROGRAMMING handoff", "bootloader identity", "REQUEST_SEED"]
  if allow_cross_calibration_send_key:
    names.append("SEND_KEY")
  for i, name in enumerate(names, 1):
    time.sleep(0.3)
    _diag_progress(steps=i, last=name)
  with diag_lock:
    message = (
      "Unknown F181: programming handoff, bootloader identity, and seed observed; counted SEND_KEY not armed. " +
      "No WDBI or payload operation was sent. (mock)"
      if not allow_cross_calibration_send_key else
      "Unknown F181: explicitly armed bootloader SEND_KEY accepted; RAM-exec geometry remains unknown, so no WDBI or payload operation was sent. (mock)"
    )
    steps = [
      {"name": "connect panda", "ok": True, "detail": "fw 1.7.0-mock", "ms": 42},
      {"name": "classify RAM-exec geometry", "ok": True, "detail": "unverified; observation continues", "ms": 1},
      {"name": "session PROGRAMMING handoff", "ok": True, "detail": "bootloader reappeared", "ms": 220},
      {"name": "security REQUEST_SEED", "ok": True, "detail": "11" * 16, "ms": 15},
    ]
    if allow_cross_calibration_send_key:
      steps.append({"name": "security SEND_KEY", "ok": True, "detail": "ok", "ms": 14})
    diag_state.update(
      status="observed",
      step_count=len(steps),
      last="security SEND_KEY" if allow_cross_calibration_send_key else "security REQUEST_SEED",
      panda="1.7.0-mock",
      eps_bus=1,
      identity=[
        {"did": "0xf181", "name": "app_sw_id", "hex": "01896546313230383030300000000000", "ascii": ".8965F1208000...."},
      ],
      bootloader_identity=[
        {"did": "0xf181", "name": "app_sw_id", "hex": "01424f4f542d554e4b4e4f574e", "ascii": ".BOOT-UNKNOWN"},
      ],
      ram_exec_geometry={"status": "unverified", "f181": "8965F1208000", "error": "no verified authenticated geometry"},
      security_seed="11" * 16,
      send_key_armed=allow_cross_calibration_send_key,
      cross_calibration_send_key=True,
      steps=steps, failed_at="", exception="", traceback="", frames=0, bytes=0, message=message,
    )


def _run_diag_job(allow_cross_calibration_send_key: bool = False) -> None:
  try:
    result = dump_diagnose(
      progress_cb=_diag_progress, allow_cross_calibration_send_key=allow_cross_calibration_send_key,
    )
    with diag_lock:
      diag_state.update(
        status=result.get("status", "failed"),
        panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1),
        identity=result.get("identity", []),
        bootloader_identity=result.get("bootloader_identity", []),
        ram_exec_geometry=result.get("ram_exec_geometry", {}),
        security_seed=result.get("security_seed", ""),
        send_key_armed=result.get("send_key_armed", False),
        cross_calibration_send_key=result.get("cross_calibration_send_key", False),
        steps=result.get("steps", []),
        step_count=len(result.get("steps", [])),
        failed_at=result.get("failed_at", ""),
        exception=result.get("exception", ""),
        traceback=result.get("traceback", ""),
        frames=result.get("frames", 0),
        bytes=result.get("bytes", 0),
        message=result.get("message", ""),
        **_route_metadata(result),
      )
  except NotAGNOSError:
    _run_diag_mock(allow_cross_calibration_send_key)
  except Exception as e:
    with diag_lock:
      diag_state.update(status="failed", message=str(e), traceback=traceback.format_exc())
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_diag_job(*, allow_cross_calibration_send_key: bool = False) -> bool:
  # panda_lock gates it against extract/dump/collect/sniff, released in the finally.
  if not panda_lock.acquire(blocking=False):
    return False
  with diag_lock:
    diag_state.update(status="running", step_count=0, last="", panda="", eps_bus=-1,
                      identity=[], bootloader_identity=[], ram_exec_geometry={}, security_seed="",
                      send_key_armed=allow_cross_calibration_send_key, cross_calibration_send_key=False,
                      steps=[], failed_at="", exception="", traceback="", frames=0, bytes=0, message="")
  try:
    threading.Thread(
      target=_run_diag_job, args=(allow_cross_calibration_send_key,), name="tsk_dataflash_diag", daemon=True,
    ).start()
  except Exception:
    with diag_lock:
      diag_state.update(status="failed", message="Could not start the diagnostic job.")
    panda_lock.release()
    return False
  return True


def _probe_progress(attempts=None, last=None) -> None:
  with probe_lock:
    if attempts is not None:
      probe_state["attempt_count"] = attempts
    if last is not None:
      probe_state["last"] = last


def _run_probe_mock() -> None:
  # Laptop dry run: model the now-understood Sienna shape — 10 02 times out while the
  # application resets, then the bootloader reappears on the exact same physical route.
  for i, name in enumerate(("discover physical route", "programming handoff"), 1):
    time.sleep(0.3)
    _probe_progress(attempts=i, last=name)
  route = {"eps_bus": 1, "eps_rx_bus": 1, "eps_tx": "0x7a1", "eps_rx": "0x7a9",
           "elm327_param": 1, "semantic_path": "normal-harness"}
  with probe_lock:
    probe_state.update(
      status="entered",
      attempt_count=2,
      last="bootloader reappeared",
      panda="1.7.0-mock",
      eps_bus=1,
      attempts=[
        {"name": "route discovery", "ok": True, "detail": str(route), "programming": False},
        {"name": "DEFAULT -> EXTENDED -> PROGRAMMING", "ok": True,
         "detail": "endpoint reappeared on preserved route after response timeout", "programming": True},
      ],
      security={}, security_levels=[], all_bus=[],
      did_it_take={"switched": True,
                   "evidence": "diagnostic endpoint reappeared on preserved route after application PROGRAMMING reset",
                   "response_timeout": True},
      route=route,
      application_f181={"hex": "0138393635463132303830303000000000", "ascii": ".8965F1208000...."},
      bootloader_f181={"hex": "0121212121212121212121212121212121", "ascii": ".!!!!!!!!!!!!!!!"},
      functional_0x777={"before": {"address": "0x777", "observed": True, "rx": "0x7a9", "rx_bus": 1},
                        "after": {"address": "0x777", "observed": True, "rx": "0x7a9", "rx_bus": 1}},
      programming_handoff={"route_before": route, "route_after": route,
                           "programming_response_timeout": True,
                           "health_before": {"bus": 1}, "health_after_reappearance": {"bus": 1}},
      message="Programming handoff completed on the preserved normal-harness route. (mock)",
    )


def _run_probe_job() -> None:
  try:
    result = probe_programming(progress_cb=_probe_progress)
    with probe_lock:
      probe_state.update(
        status=result.get("status", "failed"),
        panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1),
        attempts=result.get("attempts", []),
        attempt_count=len(result.get("attempts", [])),
        security=result.get("security", {}),
        security_levels=result.get("security_levels", []),
        did_it_take=result.get("did_it_take", {}),
        all_bus=result.get("all_bus", []),
        route=result.get("route", {}),
        application_f181=result.get("application_f181", {}),
        bootloader_f181=result.get("bootloader_f181", {}),
        functional_0x777=result.get("functional_0x777", {}),
        programming_handoff=result.get("programming_handoff", {}),
        message=result.get("message", ""),
      )
  except NotAGNOSError:
    _run_probe_mock()
  except Exception as e:
    with probe_lock:
      probe_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_probe_job() -> bool:
  # panda_lock gates it against extract/dump/collect/sniff/diag, released in the finally.
  if not panda_lock.acquire(blocking=False):
    return False
  with probe_lock:
    probe_state.update(status="running", attempt_count=0, last="", panda="", eps_bus=-1,
                       attempts=[], security={}, security_levels=[], did_it_take={}, all_bus=[],
                       route={}, application_f181={}, bootloader_f181={}, functional_0x777={},
                       programming_handoff={}, message="")
  try:
    threading.Thread(target=_run_probe_job, name="tsk_prog_probe", daemon=True).start()
  except Exception:
    with probe_lock:
      probe_state.update(status="failed", message="Could not start the probe job.")
    panda_lock.release()
    return False
  return True


def _readmem_progress(reads=None, last=None) -> None:
  with readmem_lock:
    if reads is not None:
      readmem_state["count"] = reads
    if last is not None:
      readmem_state["last"] = last


def _run_readmem_mock() -> None:
  # Laptop dry run models the exact analyzed Sienna request grammar. The historical
  # object-15 location is intentionally excluded while ordinary DataFlash and the
  # bootloader DID-0201 residue buffer are readable.
  names = ("dataflash base", "object-15 / historical key region", "boot payload-key residue",
           "d/q observation bytes", "application SecurityAccess root mirror", "legacy no-memory-id key region")
  for i, name in enumerate(names, 1):
    time.sleep(0.12)
    _readmem_progress(reads=i, last=name)
  with readmem_lock:
    readmem_state.update(
      status="read", count=6, last=names[-1], panda="1.7.0-mock", eps_bus=1,
      eps_rx_bus=1, eps_tx="0x7a1", eps_rx="0x7a9", elm327_param=1,
      semantic_path="normal-harness", f181="8965B4512000",
      f181_hex=b"8965B4512000".hex(),
      application_sa_recovery={
        "f181": "8965B4512000", "supported": True, "address": "0xfebf7be0", "memory_id": 1,
        "size": 16, "expected_root": "893e08418c741ffa2a9c044bffa55813",
        "evidence": "KEYLESS-006 exact-F181 startup LocalRAM mirror", "attempted": True,
        "recovered_root": "893e08418c741ffa2a9c044bffa55813", "matches_expected": True, "read_ok": True,
      },
      reads=[
        {"name": "dataflash base", "session": "extended", "shape": "memory-id", "memory_id": 2,
         "address": "0xff200000", "size": 16, "sienna_8965b4512000_policy": "firmware-readable",
         "request_data": "1502ff20000010", "ok": True, "detail": "112233445566778899aabbccddeeff00"},
        {"name": "object-15 / historical key region", "session": "extended", "shape": "memory-id", "memory_id": 2,
         "address": "0xff206e14", "size": 16, "sienna_8965b4512000_policy": "firmware-excluded",
         "request_data": "1502ff206e1410", "ok": False, "detail": "NRC 0x31 request out of range"},
        {"name": "boot payload-key residue", "session": "extended", "shape": "memory-id", "memory_id": 1,
         "address": "0xfebf2d08", "size": 16, "sienna_8965b4512000_policy": "firmware-readable",
         "request_data": "1501febf2d0810", "ok": True, "detail": "00112233445566778899aabbccddeeff"},
        {"name": "d/q observation bytes", "session": "extended", "shape": "memory-id", "memory_id": 1,
         "address": "0xfebe6d28", "size": 4, "sienna_8965b4512000_policy": "firmware-readable",
         "request_data": "1501febe6d2804", "ok": True, "detail": "00000000"},
        {"name": "application SecurityAccess root mirror", "session": "extended", "shape": "memory-id", "memory_id": 1,
         "address": "0xfebf7be0", "size": 16, "sienna_8965b4512000_policy": "firmware-readable",
         "request_data": "1501febf7be010", "ok": True, "detail": "893e08418c741ffa2a9c044bffa55813"},
        {"name": "legacy no-memory-id key region", "session": "extended", "shape": "ordinary", "memory_id": None,
         "address": "0xff206e14", "size": 16, "sienna_8965b4512000_policy": "different-alfid",
         "request_data": "14ff206e1410", "ok": False, "detail": "NRC 0x13 incorrect message length or invalid format"},
      ],
      message=" ".join((
        "The exact-F181 KEYLESS-006 application SecurityAccess mirror was read before SecurityAccess",
        "and matches the firmware-pinned 0x03/0x04 root. No SEND_KEY or write was sent. (mock)",
      )),
    )


def _run_readmem_job() -> None:
  try:
    result = read_key_region(progress_cb=_readmem_progress)
    with readmem_lock:
      readmem_state.update(
        status=result.get("status", "failed"), panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1), eps_rx_bus=result.get("eps_rx_bus", -1),
        eps_tx=result.get("eps_tx", ""), eps_rx=result.get("eps_rx", ""),
        f181=result.get("f181", ""), f181_hex=result.get("f181_hex", ""),
        reads=result.get("reads", []), count=len(result.get("reads", [])),
        application_sa_recovery=result.get("application_sa_recovery", {}),
        message=result.get("message", ""), **_route_metadata(result),
      )
  except NotAGNOSError:
    _run_readmem_mock()
  except Exception as e:
    with readmem_lock:
      readmem_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_readmem_job() -> bool:
  if not panda_lock.acquire(blocking=False):
    return False
  with readmem_lock:
    readmem_state.update(status="running", count=0, last="", panda="", eps_bus=-1,
                         eps_rx_bus=-1, eps_tx="", eps_rx="", f181="", f181_hex="",
                         reads=[], application_sa_recovery={}, message="")
  try:
    threading.Thread(target=_run_readmem_job, name="tsk_read_mem", daemon=True).start()
  except Exception:
    with readmem_lock:
      readmem_state.update(status="failed", message="Could not start the read-memory job.")
    panda_lock.release()
    return False
  return True


def _xcp_progress(step=None, last=None) -> None:
  with xcp_lock:
    if step is not None:
      xcp_state["step"] = str(step)
    if last is not None:
      xcp_state["last"] = str(last)


def _run_xcp_mock(profile: str) -> None:
  selected = XCP_PROFILES[profile]
  for step, last in (("connect", "CAN 0x7F7 CONNECT"), ("snapshot", "bounded F4 LocalRAM reads"),
                     ("daq", f"configure {profile}"), ("capture", "capture 0x7F8 DAQ DTOs")):
    time.sleep(0.12)
    _xcp_progress(step=step, last=last)
  snapshot = [{"address": f"0x{address:08x}", "ok": True, "value": index}
              for index, address in enumerate(selected.addresses)]
  sample_values = [{"address": row["address"], "value": row["value"]} for row in snapshot[:7]]
  with xcp_lock:
    xcp_state.update(
      status="observed", count=2, panda="1.7.0-mock", eps_bus=1, eps_rx_bus=1,
      eps_tx="0x7a1", eps_rx="0x7a9", elm327_param=1, semantic_path="normal-harness",
      f181="8965B4512000", f181_hex=b"8965B4512000".hex(), schema="tsk-xcp-daq-observer-v2", profile=profile,
      profile_description=selected.description, profile_finding_ids=list(selected.finding_ids),
      xcp_request_id="0x7f7", xcp_response_id="0x7f8",
      connect_response="ff00000000000000", snapshot=snapshot,
      frames=[{"pid": 0, "t_ms": 0.0, "raw": "0001020304050607", "values": sample_values},
              {"pid": 0, "t_ms": 2.0, "raw": "0002030405060708", "values": sample_values}],
      profile_semantics_verified=True, profile_semantics="firmware-verified for exact 8965B4512000",
      volatile_daq_configuration=True, source_memory_writes_implemented=False, write_commands_implemented=False,
      forbidden_command_opcodes={f"0x{opcode:02X}": reason for opcode, reason in sorted(XCP_FORBIDDEN_COMMANDS.items())},
      wall_clock_rate_claimed=False,
      control_timing={"requests": [{"operation": "connect", "request_hex": "ff00000000000000",
                                    "rtt_seconds": 0.001}],
                      "rtt_statistics": {"count": 1, "min_seconds": 0.001, "max_seconds": 0.001,
                                         "mean_seconds": 0.001, "median_seconds": 0.001,
                                         "jitter_seconds": 0.0, "samples_source": "time.monotonic deltas only"}},
      capture_window={"requested_duration_seconds": 1.5, "requested_max_frames": 512,
                      "truncated_by_frame_cap": False,
                      "clocks": "monotonic deltas only for intervals; UTC for cross-log correlation"},
      message=" ".join((
        f"XCP CONNECT, bounded F4 reads, and volatile DAQ observation succeeded for {profile};",
        "captured 2 DTO frame(s). No XCP source-memory write command was implemented. (mock)",
      )),
    )


def _run_xcp_job(profile: str) -> None:
  try:
    result = probe_xcp(profile=profile, progress_cb=_xcp_progress)
    with xcp_lock:
      xcp_state.update(
        status=result.get("status", "failed"), panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1), eps_rx_bus=result.get("eps_rx_bus", -1),
        eps_tx=result.get("eps_tx", ""), eps_rx=result.get("eps_rx", ""),
        f181=result.get("f181", ""), f181_hex=result.get("f181_hex", ""),
        schema=result.get("schema", ""), profile=result.get("profile", profile),
        profile_description=result.get("profile_description", ""),
        profile_finding_ids=result.get("profile_finding_ids", []),
        xcp_request_id=result.get("xcp_request_id", "0x7f7"),
        xcp_response_id=result.get("xcp_response_id", "0x7f8"),
        connect_response=result.get("connect_response", ""), snapshot=result.get("snapshot", []),
        frames=result.get("frames", []), count=len(result.get("frames", [])),
        profile_semantics_verified=bool(result.get("profile_semantics_verified", False)),
        profile_semantics=result.get("profile_semantics", ""),
        volatile_daq_configuration=bool(result.get("volatile_daq_configuration", True)),
        source_memory_writes_implemented=bool(result.get("source_memory_writes_implemented", False)),
        write_commands_implemented=bool(result.get("write_commands_implemented", False)),
        forbidden_command_opcodes=result.get("forbidden_command_opcodes", {}),
        wall_clock_rate_claimed=bool(result.get("wall_clock_rate_claimed", False)),
        control_timing=result.get("control_timing", {"requests": [], "rtt_statistics": None}),
        capture_window=result.get("capture_window", {}),
        message=result.get("message", ""),
        **_route_metadata(result),
      )
      if result.get("cleanup_error"):
        xcp_state["cleanup_error"] = result["cleanup_error"]
      if result.get("daq_error"):
        xcp_state["daq_error"] = result["daq_error"]
  except NotAGNOSError:
    _run_xcp_mock(profile)
  except Exception as e:
    with xcp_lock:
      xcp_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_xcp_job(profile: str = "actuation-discriminator") -> bool:
  if profile not in XCP_PROFILES:
    return False
  if not panda_lock.acquire(blocking=False):
    return False
  with xcp_lock:
    xcp_state.update(
      status="running", count=0, last="", step="", panda="", eps_bus=-1, eps_rx_bus=-1,
      eps_tx="", eps_rx="", f181="", f181_hex="", profile=profile,
      profile_description=XCP_PROFILES[profile].description,
      profile_finding_ids=list(XCP_PROFILES[profile].finding_ids), connect_response="", snapshot=[], frames=[],
      schema="tsk-xcp-daq-observer-v2", profile_semantics_verified=False, profile_semantics="",
      volatile_daq_configuration=True, source_memory_writes_implemented=False, cleanup_error="", daq_error="",
      write_commands_implemented=False, forbidden_command_opcodes={}, wall_clock_rate_claimed=False,
      control_timing={"requests": [], "rtt_statistics": None}, capture_window={}, message="",
    )
  try:
    threading.Thread(target=_run_xcp_job, args=(profile,), name="tsk_xcp_observer", daemon=True).start()
  except Exception:
    with xcp_lock:
      xcp_state.update(status="failed", message="Could not start the XCP observer job.")
    panda_lock.release()
    return False
  return True


def _ephemeral_progress(step=None, message=None) -> None:
  with ephemeral_lock:
    if step is not None:
      ephemeral_state["step"] = str(step)
    if message is not None:
      ephemeral_state["message"] = str(message)


def _run_ephemeral_mock(f181: str) -> None:
  for step, message in (
      ("identified", f"F181 {f181}; runtime package and route bound"),
      ("programming", "bootloader reappeared on preserved route"),
      ("bootstrap-authenticated", "target-accepted bootstrap passed 0x10F0"),
      ("heartbeat", "heartbeat advanced 0x10 -> 0x20"),
      ("reset-to-stock", "heartbeat stopped after reset"),
  ):
    time.sleep(0.08)
    _ephemeral_progress(step=step, message=message)
  result = {
    "status": "passed", "f181": f181, "scheduler_observed": True,
    "reset_to_stock_verified": True, "bridge_execution_exposed": False, "mock": True,
  }
  with ephemeral_lock:
    ephemeral_state.update(status="passed", result=result, message="Inert scheduler canary passed (mock).")


def _run_ephemeral_canary_job(f181: str) -> None:
  try:
    result = run_inert_canary(expected_f181=f181, bench_isolated=True, progress_cb=_ephemeral_progress)
    with ephemeral_lock:
      ephemeral_state.update(status="passed", result=result, message=(
        "Inert scheduler canary heartbeat and reset-to-stock proof passed. " +
        "The steering bridge remains unavailable in TSK."
      ))
  except NotAGNOSError:
    _run_ephemeral_mock(f181)
  except Exception as e:
    with ephemeral_lock:
      ephemeral_state.update(status="failed", message=str(e), result={})
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_ephemeral_canary_job(f181: str, *, bench_isolated: bool) -> bool:
  target = normalize_f181(f181)
  if not target or not bench_isolated:
    return False
  runtime = public_runtime_status(target)
  if not runtime.get("live_canary_ready"):
    return False
  if not panda_lock.acquire(blocking=False):
    return False
  with ephemeral_lock:
    ephemeral_state.update(
      status="running", step="", message="", f181=target, package=runtime, result={},
      bridge_execution_exposed=False,
    )
  try:
    threading.Thread(target=_run_ephemeral_canary_job, args=(target,),
                     name="tsk_ephemeral_canary", daemon=True).start()
  except Exception:
    with ephemeral_lock:
      ephemeral_state.update(status="failed", message="Could not start the inert canary job.")
    panda_lock.release()
    return False
  return True


def _ident_progress(items=None, last=None) -> None:
  with ident_lock:
    if items is not None:
      ident_state["count"] = items
    if last is not None:
      ident_state["last"] = last


def _run_ident_mock() -> None:
  for i in range(1, 6):
    time.sleep(0.25)
    _ident_progress(items=i * 4, last=f"item {i * 4}")
  with ident_lock:
    ident_state.update(
      status="mapped", count=24, last="0x19 read DTC info", panda="1.7.0-mock",
      eps_bus=1, eps_rx_bus=1, eps_tx="0x7a1", eps_rx="0x7a9",
      identity=[
        {"did": "0xf181", "name": "app_sw_id", "hex": "383936354631323038303030", "ascii": "8965F1208000"},
        {"did": "0xf186", "name": "active_session", "hex": "03", "ascii": "."},
        {"did": "0xf187", "name": "spare_part_no", "hex": "", "ascii": "NRC 0x31 requestOutOfRange"},
        {"did": "0xf18c", "name": "ecu_serial", "hex": "38393635303132", "ascii": "8965012"},
        {"did": "0xf190", "name": "vin", "hex": "", "ascii": "NRC 0x31 requestOutOfRange"},
      ],
      services=[
        {"name": "0x10 session control", "supported": True, "detail": "supported"},
        {"name": "0x22 read data by id", "supported": True, "detail": "supported"},
        {"name": "0x23 read memory", "supported": True, "detail": "supported (NRC 0x33 securityAccessDenied)"},
        {"name": "0x27 security access", "supported": True, "detail": "supported (NRC 0x7e subFunctionNotSupportedInActiveSession)"},
        {"name": "0x3e tester present", "supported": True, "detail": "supported"},
        {"name": "0x19 read DTC info", "supported": True, "detail": "supported"},
      ],
      message="Read 3 identity field(s); 6 of 6 probed services answered. (mock)",
    )


def _run_ident_job() -> None:
  try:
    result = map_surface(progress_cb=_ident_progress)
    with ident_lock:
      ident_state.update(
        status=result.get("status", "failed"), panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1), eps_rx_bus=result.get("eps_rx_bus", -1),
        eps_tx=result.get("eps_tx", ""), eps_rx=result.get("eps_rx", ""),
        identity=result.get("identity", []), services=result.get("services", []),
        count=len(result.get("identity", [])) + len(result.get("services", [])),
        message=result.get("message", ""),
        **_route_metadata(result),
      )
  except NotAGNOSError:
    _run_ident_mock()
  except Exception as e:
    with ident_lock:
      ident_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_ident_job() -> bool:
  if not panda_lock.acquire(blocking=False):
    return False
  with ident_lock:
    ident_state.update(status="running", count=0, last="", panda="", eps_bus=-1,
                       eps_rx_bus=-1, eps_tx="", eps_rx="", identity=[], services=[],
                       message="")
  try:
    threading.Thread(target=_run_ident_job, name="tsk_ident_map", daemon=True).start()
  except Exception:
    with ident_lock:
      ident_state.update(status="failed", message="Could not start the identity-map job.")
    panda_lock.release()
    return False
  return True


def _reset_progress(attempts=None, last=None) -> None:
  with reset_lock:
    if attempts is not None:
      reset_state["count"] = attempts
    if last is not None:
      reset_state["last"] = last


def _run_reset_mock() -> None:
  for i in range(1, 5):
    time.sleep(0.3)
    _reset_progress(attempts=i, last=f"{i * 900}ms timeout")
  with reset_lock:
    reset_state.update(
      status="blocked", count=4, last="2700ms timeout", panda="1.7.0-mock", eps_bus=1,
      reset="hard reset accepted",
      attempts=[
        {"t_ms": 5, "detail": "timeout"},
        {"t_ms": 900, "detail": "timeout"},
        {"t_ms": 1800, "detail": "timeout"},
        {"t_ms": 2700, "detail": "timeout"},
      ],
      session_after="NRC 0x31 requestOutOfRange",
      message="No PROGRAMMING acceptance in the reset window. Active session after reset: " +
              "NRC 0x31 requestOutOfRange (0x02 would mean it switched silently). (mock)",
    )


def _run_reset_job() -> None:
  try:
    result = probe_reset_window(progress_cb=_reset_progress)
    with reset_lock:
      reset_state.update(
        status=result.get("status", "failed"), panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1), reset=result.get("reset", ""),
        attempts=result.get("attempts", []), count=len(result.get("attempts", [])),
        session_after=result.get("session_after", ""), message=result.get("message", ""),
        **_route_metadata(result),
      )
  except NotAGNOSError:
    _run_reset_mock()
  except Exception as e:
    with reset_lock:
      reset_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_reset_job() -> bool:
  if not panda_lock.acquire(blocking=False):
    return False
  with reset_lock:
    reset_state.update(status="running", count=0, last="", panda="", eps_bus=-1,
                       reset="", attempts=[], session_after="", message="")
  try:
    threading.Thread(target=_run_reset_job, name="tsk_reset_probe", daemon=True).start()
  except Exception:
    with reset_lock:
      reset_state.update(status="failed", message="Could not start the reset-probe job.")
    panda_lock.release()
    return False
  return True


def _level3_progress(tests=None, last=None) -> None:
  with level3_lock:
    if tests is not None:
      level3_state["count"] = tests
    if last is not None:
      level3_state["last"] = last


def _run_level3_mock() -> None:
  # Laptop dry run: the reproduced shape — 0x03 answers from a clean extended session.
  for i, name in enumerate(("clean extended (0x03 first)", "default session (no extended)",
                            "0x01 first, then 0x03", "programming poke, then 0x03"), 1):
    time.sleep(0.3)
    _level3_progress(tests=i, last=name)
  with level3_lock:
    level3_state.update(
      status="reproduced", count=4, last="programming poke, then 0x03", panda="1.7.0-mock", eps_bus=1,
      seeds=["da2df2eff64d95f5426bf3af70bb49aa", "1c9a4f0b77e3d5218a6c4b0fe29d3a11",
             "77aa10c4be5518e2049f3c6d1b8e720d", "9be1035fac82d4761e0b5528cf94a6d3"],
      primer="",
      tests=[
        {"name": "clean extended (0x03 first)", "got_seed": True,
         "seed": "da2df2eff64d95f5426bf3af70bb49aa",
         "steps": [
           {"step": "default", "detail": "accepted"},
           {"step": "extended", "detail": "accepted"},
           {"step": "seed 0x03", "detail": "seed da2df2eff64d95f5426bf3af70bb49aa"},
           {"step": "seed 0x03 again", "detail": "seed 1c9a4f0b77e3d5218a6c4b0fe29d3a11"},
         ]},
        {"name": "default session (no extended)", "got_seed": False, "seed": "",
         "steps": [
           {"step": "default", "detail": "accepted"},
           {"step": "seed 0x03", "detail": "NRC 0x7e subFunctionNotSupportedInActiveSession"},
         ]},
        {"name": "0x01 first, then 0x03", "got_seed": True,
         "seed": "77aa10c4be5518e2049f3c6d1b8e720d",
         "steps": [
           {"step": "default", "detail": "accepted"},
           {"step": "extended", "detail": "accepted"},
           {"step": "seed 0x01", "detail": "NRC 0x7e subFunctionNotSupportedInActiveSession"},
           {"step": "seed 0x03", "detail": "seed 77aa10c4be5518e2049f3c6d1b8e720d"},
         ]},
        {"name": "programming poke, then 0x03", "got_seed": True,
         "seed": "9be1035fac82d4761e0b5528cf94a6d3",
         "steps": [
           {"step": "default", "detail": "accepted"},
           {"step": "extended", "detail": "accepted"},
           {"step": "poke programming", "detail": "sent 10 02 (ignored response)"},
           {"step": "seed 0x03", "detail": "seed 9be1035fac82d4761e0b5528cf94a6d3"},
         ]},
      ],
      message="Level 0x03 returned a seed from a clean extended session on bus 1 (seeds differ each " +
              "request) — it is its own input/output, not a side effect of prior traffic. (mock)",
    )


def _run_level3_job() -> None:
  try:
    result = probe_level3(progress_cb=_level3_progress)
    with level3_lock:
      level3_state.update(
        status=result.get("status", "failed"), panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1), tests=result.get("tests", []),
        seeds=result.get("seeds", []), primer=result.get("primer", ""),
        count=len(result.get("tests", [])), message=result.get("message", ""),
        **_route_metadata(result),
      )
  except NotAGNOSError:
    _run_level3_mock()
  except Exception as e:
    with level3_lock:
      level3_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_level3_job() -> bool:
  if not panda_lock.acquire(blocking=False):
    return False
  with level3_lock:
    level3_state.update(status="running", count=0, last="", panda="", eps_bus=-1,
                        tests=[], seeds=[], primer="", message="")
  try:
    threading.Thread(target=_run_level3_job, name="tsk_level3_probe", daemon=True).start()
  except Exception:
    with level3_lock:
      level3_state.update(status="failed", message="Could not start the level-0x03 probe.")
    panda_lock.release()
    return False
  return True


def _sendkey_progress(step=None, last=None) -> None:
  with sendkey_lock:
    if last is not None:
      sendkey_state["last"] = last


def _run_sendkey_mock(allow_cross_calibration: bool = False) -> None:
  # Laptop dry run defaults to the safe cross-calibration boundary: identify an
  # unknown target and stop before a counted SEND_KEY unless explicitly armed.
  _sendkey_progress(step="identity", last="8965F1208000")
  time.sleep(0.2)
  with sendkey_lock:
    if not allow_cross_calibration:
      sendkey_state.update(
        status="armed_required", last="identity", panda="1.7.0-mock", eps_bus=1,
        session="", seed="", key="", send_key="", post_unlock_reads=[],
        target_f181=".8965F1208000....", target_f181_hex="0138393635463132303830303000000000",
        cross_calibration=True, armed=False,
        message="Unknown calibration identified; no SEND_KEY sent without explicit arming. (mock)",
      )
      return

  for step in ("extended", "seed", "key", "send_key"):
    time.sleep(0.2)
    _sendkey_progress(step=step, last=step)
  with sendkey_lock:
    sendkey_state.update(
      status="invalid_key", last="send_key", panda="1.7.0-mock", eps_bus=1, session="extended",
      seed="da2df2eff64d95f5426bf3af70bb49aa",
      key="3f9c1a04d8b27e6510c23a9fbe4d7182",
      send_key="NRC 0x35 invalidKey", post_unlock_reads=[],
      target_f181=".8965F1208000....", target_f181_hex="0138393635463132303830303000000000",
      cross_calibration=True, armed=True,
      message="8965B4512000 application 0x03/0x04 derivation rejected on the armed target. (mock)",
    )


def _run_sendkey_job(allow_cross_calibration: bool = False) -> None:
  try:
    result = send_sienna_application_key(progress_cb=_sendkey_progress,
                                         allow_cross_calibration=allow_cross_calibration)
    with sendkey_lock:
      sendkey_state.update(
        status=result.get("status", "failed"), panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1), session=result.get("session", ""),
        seed=result.get("seed", ""), key=result.get("key", ""),
        send_key=result.get("send_key", ""),
        post_unlock_reads=result.get("post_unlock_reads", []),
        target_f181=result.get("target_f181", ""),
        target_f181_hex=result.get("target_f181_hex", ""),
        cross_calibration=result.get("cross_calibration", False),
        armed=result.get("armed", False),
        message=result.get("message", ""),
        **_route_metadata(result),
      )
  except NotAGNOSError:
    _run_sendkey_mock(allow_cross_calibration)
  except Exception as e:
    with sendkey_lock:
      sendkey_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_sendkey_job(*, allow_cross_calibration: bool = False) -> bool:
  if not panda_lock.acquire(blocking=False):
    return False
  with sendkey_lock:
    sendkey_state.update(status="running", last="", panda="", eps_bus=-1, session="",
                         seed="", key="", send_key="", post_unlock_reads=[], target_f181="",
                         target_f181_hex="", cross_calibration=False, armed=allow_cross_calibration,
                         message="")
  try:
    threading.Thread(target=_run_sendkey_job, args=(allow_cross_calibration,),
                     name="tsk_sendkey_probe", daemon=True).start()
  except Exception:
    with sendkey_lock:
      sendkey_state.update(status="failed", message="Could not start the send-key probe.")
    panda_lock.release()
    return False
  return True


def _preamble_progress(steps=None, last=None) -> None:
  with preamble_lock:
    if steps is not None:
      preamble_state["count"] = steps
    if last is not None:
      preamble_state["last"] = last


def _run_preamble_mock() -> None:
  # Laptop dry run: the expected in-car shape — no lock, programming still refused, and
  # the DTC diff empty (the reading that points at a lower-layer drop).
  for i, name in enumerate(("lock read", "0x01 baseline", "exploit surface",
                            "0x85 -> programming", "0x85 + 0x28 -> programming",
                            "0x85 + 0x28 -> programming (6s)",
                            "0x85 + 0x28 -> 10 82 suppressed",
                            "functional 0x28 -> programming", "DTC diff"), 1):
    time.sleep(0.25)
    _preamble_progress(steps=i, last=name)

  def variant(name, prog):
    return {
      "name": name, "opened": False, "programming": prog, "session_after": "0x03",
      "seed_01_after": "NRC 0x7e subFunctionNotSupportedInActiveSession",
      "steps": [
        {"step": "extended", "detail": "accepted"},
        {"step": "0x85 DTC off", "detail": "accepted"},
        {"step": "0x28 disable tx", "detail": "accepted"},
      ],
    }

  with preamble_lock:
    preamble_state.update(
      status="blocked", count=9, last="DTC diff", panda="1.7.0-mock", eps_bus=1,
      identity=[
        {"name": "app_sw_id", "ok": True, "detail": "8965F1208000 (383936354631323038303030)"},
        {"name": "ecu_serial", "ok": True, "detail": "8965012N50E12H030731 (38393635…)"},
        {"name": "active_session", "ok": True, "detail": "0x03"},
      ],
      lock={
        "extended": "accepted",
        "seed_03": "seed 5b1e9c77aa304f628d1b0e5942cf7a83",
        "seed_01_baseline": "NRC 0x7e subFunctionNotSupportedInActiveSession",
        "locked": False,
      },
      services=[
        {"name": "extended", "ok": True, "detail": "accepted"},
        {"name": "read DID 0x201 (did_201_key)", "ok": False,
         "detail": "NRC 0x31 requestOutOfRange"},
        {"name": "read DID 0x202 (did_202_iv)", "ok": False,
         "detail": "NRC 0x31 requestOutOfRange"},
        {"name": "read DID 0x203 (did_203_state)", "ok": False,
         "detail": "NRC 0x31 requestOutOfRange"},
        {"name": "routine results 0x10f0", "ok": False,
         "detail": "NRC 0x7f serviceNotSupportedInActiveSession"},
        {"name": "request download (RAM)", "ok": False,
         "detail": "NRC 0x7f serviceNotSupportedInActiveSession"},
        {"name": "0x85 DTC setting OFF", "ok": True, "detail": "accepted"},
        {"name": "0x28 comm control disable-tx", "ok": True, "detail": "accepted"},
        {"name": "DTC snapshot (before)", "ok": True, "detail": "3 codes"},
      ],
      variants=[
        variant("0x85 -> programming", "MessageTimeoutError"),
        variant("0x85 + 0x28 -> programming", "MessageTimeoutError"),
        variant("0x85 + 0x28 -> programming (6s)", "MessageTimeoutError"),
        variant("0x85 + 0x28 -> 10 82 suppressed", "sent (suppressed) — see session read"),
        variant("functional 0x28 -> programming", "MessageTimeoutError"),
      ],
      dtc={"before": ["c11234:08", "c15678:2f", "c1aa01:08"],
           "after": ["c11234:08", "c15678:2f", "c1aa01:08"], "new": []},
      reads=[
        {"name": "key region 0xff206e14", "ok": False, "detail": "NRC 0x31 requestOutOfRange"},
        {"name": "dataflash base 0xff200000", "ok": False, "detail": "NRC 0x31 requestOutOfRange"},
        {"name": "ram window 0xfebf0000", "ok": False, "detail": "NRC 0x31 requestOutOfRange"},
      ],
      liveness="EPS still answering at end of run",
      message="Programming still refused with the pre-programming preamble (0 new DTC(s)). " +
              "Level 0x01 stayed shut. Export the evidence bundle — the DTC diff and service " +
              "refusal codes are the useful part of this run even though programming did not " +
              "open. (mock)",
    )


def _run_preamble_job() -> None:
  try:
    result = probe_preamble(progress_cb=_preamble_progress)
    with preamble_lock:
      preamble_state.update(
        status=result.get("status", "failed"), panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1), identity=result.get("identity", []),
        lock=result.get("lock", {}), services=result.get("services", []),
        variants=result.get("variants", []), dtc=result.get("dtc", {}),
        reads=result.get("reads", []), liveness=result.get("liveness", ""),
        message=result.get("message", ""),
        **_route_metadata(result),
      )
  except NotAGNOSError:
    _run_preamble_mock()
  except Exception as e:
    with preamble_lock:
      preamble_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_preamble_job() -> bool:
  if not panda_lock.acquire(blocking=False):
    return False
  with preamble_lock:
    preamble_state.update(status="running", count=0, last="", panda="", eps_bus=-1,
                          identity=[], lock={}, services=[], variants=[], dtc={},
                          reads=[], liveness="", message="")
  try:
    threading.Thread(target=_run_preamble_job, name="tsk_preamble_probe", daemon=True).start()
  except Exception:
    with preamble_lock:
      preamble_state.update(status="failed", message="Could not start the preamble probe.")
    panda_lock.release()
    return False
  return True


def _sweep_progress(steps=None, last=None, stage=None) -> None:
  with sweep_lock:
    if steps is not None:
      sweep_state["count"] = steps
    if last is not None:
      sweep_state["last"] = last
    if stage is not None:
      sweep_state["stage"] = stage


def _run_sweep_mock() -> None:
  # Laptop dry run: the partial shape — the budget runs out mid sub-function sweep, which
  # is the expected first-session outcome in the car.
  for i, (stage, last) in enumerate((
      ("calibrate", "calibrated"), ("services", "services default"),
      ("services", "services extended"), ("subfunctions", "sub-functions of 0x10"),
      ("subfunctions", "sub-functions of 0x22"), ("dids", "DIDs identity"),
      ("addresses", "address sweep"), ("cross", "cross-ECU silent set")), 1):
    time.sleep(0.25)
    _sweep_progress(steps=i * 64, last=last, stage=stage)
  with sweep_lock:
    sweep_state.update(
      status="partial", count=812, last="sub-functions of 0x27", stage="subfunctions",
      panda="1.7.0-mock", eps_tx="0x7a1", eps_bus=1, eps_rx_bus=1, eps_rx="0x7a9",
      timeout_ms=120, records=812,
      stages=[
        {"name": "calibrate", "detail": "round trip 12 ms → timeout 120 ms"},
        {"name": "services/default", "detail": "256 sent"},
        {"name": "services/extended", "detail": "256 sent"},
        {"name": "subfunctions/10", "detail": "256 sent"},
        {"name": "dids/identity", "detail": "44 sent"},
        {"name": "addresses", "detail": "3 responder(s)"},
      ],
      answering=["0x10", "0x14", "0x19", "0x22", "0x23", "0x27", "0x2e", "0x31", "0x3e"],
      silent=["0x28", "0x34", "0x36", "0x37", "0x85"],
      responders=["0x7a1", "0x7b0", "0x7e0"],
      frontier="subfunctions: stopped at 0x27 sub 0x40",
      hypotheses=[{"request": "1002", "label": "programming session"}],
      message="Budget reached — 812 results saved. subfunctions: stopped at 0x27 sub 0x40. " +
              "Run this page again (Not Ready to Drive) and it resumes where it stopped. " +
              "Export the evidence bundle before continuing. (mock)",
    )


def _run_sweep_job() -> None:
  try:
    result = sweep(progress_cb=_sweep_progress)
    with sweep_lock:
      sweep_state.update(
        status=result.get("status", "failed"), panda=result.get("panda", ""),
        eps_tx=result.get("eps_tx", ""), eps_bus=result.get("eps_bus", -1),
        eps_rx_bus=result.get("eps_rx_bus", -1), eps_rx=result.get("eps_rx", ""),
        timeout_ms=result.get("timeout_ms", 0),
        stages=result.get("stages", []), answering=result.get("answering", []),
        silent=result.get("silent", []), responders=result.get("responders", []),
        responder_routes=result.get("responder_routes", []), records=result.get("records", 0),
        frontier=result.get("frontier", ""),
        hypotheses=result.get("hypotheses", []), message=result.get("message", ""),
        **_route_metadata(result),
      )
  except NotAGNOSError:
    _run_sweep_mock()
  except Exception as e:
    with sweep_lock:
      sweep_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_sweep_job() -> bool:
  if not panda_lock.acquire(blocking=False):
    return False
  with sweep_lock:
    sweep_state.update(status="running", count=0, last="", stage="", panda="",
                       eps_tx="", eps_bus=-1, eps_rx_bus=-1, eps_rx="", timeout_ms=0,
                       stages=[], answering=[], silent=[], responders=[], responder_routes=[],
                       records=0, frontier="", hypotheses=[], message="")
  try:
    threading.Thread(target=_run_sweep_job, name="tsk_uds_sweep", daemon=True).start()
  except Exception:
    with sweep_lock:
      sweep_state.update(status="failed", message="Could not start the UDS sweep.")
    panda_lock.release()
    return False
  return True


def _ready_progress(steps=None, last=None, stage=None) -> None:
  with ready_lock:
    if steps is not None:
      ready_state["count"] = steps
    if last is not None:
      ready_state["last"] = last
    if stage is not None:
      ready_state["stage"] = stage


def _run_ready_mock() -> None:
  for i, last in enumerate(("capturing 30s / 90s", "capturing 90s / 90s",
                            "passive capture analysed"), 1):
    time.sleep(0.3)
    _ready_progress(steps=i * 14000, last=last, stage="passive capture")
  with ready_lock:
    ready_state.update(
      status="captured", count=41208, last="passive capture analysed",
      stage="passive capture", mode="passive", run_id="ready-passive-mock",
      panda="1.7.0-mock", eps_bus=-1, frames=41208, tx_echoes_filtered=0,
      path="/cache/tsk/uds-sweep/ready_capture.ndjson",
      capture={
        "ids": 147, "frames": 41208,
        "candidates": [
          {"bus": 1, "addr": "0x1c4", "samples": 1780, "tail_distinct": 0.998, "head_distinct": 0.061},
          {"bus": 1, "addr": "0x260", "samples": 1774, "tail_distinct": 0.996, "head_distinct": 0.044},
          {"bus": 1, "addr": "0x2a1", "samples": 890, "tail_distinct": 0.991, "head_distinct": 0.112},
        ],
        "hypothesis_hits": [
          {"bus": 1, "addr": "0x2e4", "samples": 20,
           "annotation": "prior Sienna/Corolla protected-ID hypothesis"},
        ],
        "sync": [{"bus": 1, "addr": "0x00f", "samples": 88, "distinct": 88,
                  "annotation": "prior Toyota sync hypothesis"}],
      },
      diff=[], responders=[], cross=[], seeds=[],
      message="Passively captured 41208 frames across 147 IDs. No diagnostic requests were sent. (mock)",
    )


def _run_ready_job() -> None:
  try:
    result = capture_ready(progress_cb=_ready_progress)
    with ready_lock:
      ready_state.update(
        status=result.get("status", "failed"), mode=result.get("mode", "passive"),
        run_id=result.get("run_id", ""), panda=result.get("panda", ""),
        eps_bus=result.get("eps_bus", -1), capture=result.get("capture", {}),
        diff=[], responders=[], cross=[], seeds=[], frames=result.get("frames", 0),
        tx_echoes_filtered=result.get("tx_echoes_filtered", 0),
        path=result.get("path", ""), message=result.get("message", ""),
        **_route_metadata(result),
      )
  except NotAGNOSError:
    _run_ready_mock()
  except Exception as e:
    with ready_lock:
      ready_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_ready_job() -> bool:
  if not panda_lock.acquire(blocking=False):
    return False
  with ready_lock:
    ready_state.update(status="running", count=0, last="", stage="passive capture",
                       mode="passive", run_id="", panda="", eps_bus=-1, capture={},
                       diff=[], responders=[], cross=[], seeds=[], frames=0,
                       tx_echoes_filtered=0, path="", message="")
  try:
    threading.Thread(target=_run_ready_job, name="tsk_ready_capture", daemon=True).start()
  except Exception:
    with ready_lock:
      ready_state.update(status="failed", message="Could not start the READY capture.")
    panda_lock.release()
    return False
  return True


def _ready_diff_progress(steps=None, last=None, stage=None) -> None:
  with ready_diff_lock:
    if steps is not None:
      ready_diff_state["count"] = steps
    if last is not None:
      ready_diff_state["last"] = last
    if stage is not None:
      ready_diff_state["stage"] = stage


def _run_ready_diff_mock() -> None:
  for i, last in enumerate(("service 0x28", "service 0x34", "service 0x85"), 1):
    time.sleep(0.2)
    _ready_diff_progress(steps=i, last=last, stage="active diff")
  with ready_diff_lock:
    ready_diff_state.update(
      status="complete", count=3, last="service 0x85", stage="active diff",
      mode="active_diff", run_id="ready-diff-mock", panda="1.7.0-mock",
      eps_tx="0x7a1", eps_bus=1, eps_rx_bus=1, eps_rx="0x7a9",
      diff=[
        {"label": "service 0x28", "request": "28", "outcome": "silent", "nrc": -1, "raw": ""},
        {"label": "service 0x34", "request": "34", "outcome": "silent", "nrc": -1, "raw": ""},
        {"label": "service 0x85", "request": "85", "outcome": "nrc", "nrc": 0x22, "raw": "7f8522"},
      ],
      frames=0, path="/cache/tsk/uds-sweep/ready_diff.ndjson",
      message="Replayed 3 previously characterized bare-service requests. (mock)",
    )


def _run_ready_diff_job() -> None:
  try:
    result = run_ready_diff(progress_cb=_ready_diff_progress)
    with ready_diff_lock:
      ready_diff_state.update(
        status=result.get("status", "failed"), mode=result.get("mode", "active_diff"),
        run_id=result.get("run_id", ""), panda=result.get("panda", ""),
        eps_tx=result.get("eps_tx", ""), eps_bus=result.get("eps_bus", -1),
        eps_rx_bus=result.get("eps_rx_bus", -1), eps_rx=result.get("eps_rx", ""),
        diff=result.get("diff", []),
        frames=result.get("frames", 0), path=result.get("path", ""),
        message=result.get("message", ""),
        **_route_metadata(result),
      )
  except NotAGNOSError:
    _run_ready_diff_mock()
  except Exception as e:
    with ready_diff_lock:
      ready_diff_state.update(status="failed", message=str(e))
  finally:
    TSKExtractor._close_panda()
    panda_lock.release()


def start_ready_diff_job() -> bool:
  if not panda_lock.acquire(blocking=False):
    return False
  with ready_diff_lock:
    ready_diff_state.update(status="running", count=0, last="", stage="active diff",
                            mode="active_diff", run_id="", panda="", eps_tx="",
                            eps_bus=-1, eps_rx_bus=-1, eps_rx="", diff=[], frames=0,
                            path="", message="")
  try:
    threading.Thread(target=_run_ready_diff_job, name="tsk_ready_diff", daemon=True).start()
  except Exception:
    with ready_diff_lock:
      ready_diff_state.update(status="failed", message="Could not start the READY active diff.")
    panda_lock.release()
    return False
  return True


class TSKWebHandler(BaseHTTPRequestHandler):
  server_version = "TSKWeb/0.1"

  def _send_extract_dry_run(self) -> None:
    global dry_run_counter
    scenario = dry_run_counter % 3
    dry_run_counter += 1

    if scenario == 0:
      verification = {
        "status": "found", "domain": "sync+protected", "matches": 64,
        "sync": "8/8", "protected": "56/56",
        "protected_by_id": {"0x131": 20, "0x183": 16, "0x2e4": 20},
        "protected_by_bus": {"1": 56},
        "legacy_lateral_ready": True,
        "legacy_lateral_matches_by_id": {"0x131": 20, "0x2e4": 20},
        "legacy_longitudinal_ready": True,
        "legacy_longitudinal_matches_by_id": {"0x183": 16},
      }
      recovered = persist_recovered_key(DRY_RUN_FAKE_KEY, verification, source="dry-run")
      self._send_json({
        "ok": True,
        "status": "key_recovered",
        "key": DRY_RUN_FAKE_KEY,
        "recovered_key": recovered,
        "message": (f"Cryptographically verified key recovered (dry run):\n{format_key(DRY_RUN_FAKE_KEY)}\n\n" +
                    "It has NOT been installed as SecOCKey. Target-profile and stationary verification remain."),
      })
    elif scenario == 1:
      self._send_json({
        "ok": False,
        "message": "pandad is not running.\n\nTry again. If the problem persists, turn off the car, " +
                   "put it back into 'Not Ready to Drive' mode, and then try again." +
                   f"\n\n{PING_REPORT}",
      }, status=HTTPStatus.CONFLICT)
    else:
      self._send_json({
        "ok": False,
        "message": (
          "UDS request timed out\n\n" +
          "Traceback (most recent call last):\n" +
          '  File "/data/openpilot/tsk/lib/extractor.py", line 384, in run\n' +
          "    secoc_key = cls.hack()\n" +
          '  File "/data/openpilot/tsk/lib/extractor.py", line 241, in hack\n' +
          "    seed = cls._security_access(panda)\n" +
          '  File "/data/openpilot/tsk/lib/extractor.py", line 152, in _security_access\n' +
          "    resp = cls._uds_request(panda, service=0x27, subfunction=0x01)\n" +
          '  File "/data/openpilot/tsk/lib/extractor.py", line 113, in _uds_request\n' +
          "    raise RetryError(f\"UDS request timed out\")\n" +
          "tsk.lib.extractor.RetryError: UDS request timed out\n\n" +
          "!!!! Unexpected error. Preserve raw logs and export the evidence bundle before continuing.\n"
        ),
      }, status=HTTPStatus.INTERNAL_SERVER_ERROR)

  def do_GET(self) -> None:
    self._handle_request(send_body=True)

  def do_HEAD(self) -> None:
    self._handle_request(send_body=False)

  def do_POST(self) -> None:
    path = urlparse(self.path).path
    try:
      record_operation(path, client=self.client_address[0],
                       vehicle_state=expected_vehicle_state(path))
    except OSError:
      pass

    if path == "/api/extract":
      if not panda_lock.acquire(blocking=False):
        self._send_json({
          "ok": False,
          "message": "Another panda operation (dump or CAN collect) is in progress.",
        }, status=HTTPStatus.CONFLICT)
        return

      try:
        # Do not spend a programming/extraction attempt unless enough persisted CAN
        # evidence already exists to cryptographically validate the returned bytes.
        from tsk.lib.matcher import MATCH_FLOOR, MIN_SYNC_MATCHES, load_oracle_analysis, verify_candidate_from_oracle
        try:
          oracle_analysis = load_oracle_analysis(can_oracle_path())
        except OSError:
          oracle_analysis = {"sync_samples": [], "protected_samples": [], "streams": []}
        sync_count = len(oracle_analysis["sync_samples"])
        protected_count = len(oracle_analysis["protected_samples"])
        if sync_count < MIN_SYNC_MATCHES or (sync_count + protected_count) < MATCH_FLOOR:
          self._send_json({
            "ok": False,
            "status": "oracle_required",
            "profile_discovery": {"streams": oracle_analysis.get("streams", []),
                                  "can_inventory": oracle_analysis.get("can_inventory", [])},
            "message": ("Collect target-profile CAN evidence before extraction. Current usable oracle: " +
                        f"{sync_count} sync + {protected_count} known/discovered protected samples; " +
                        f"need at least {MIN_SYNC_MATCHES} sync and {MATCH_FLOOR} total samples. " +
                        "No programming request was sent. Current openpilot IDs are compatibility evidence, not an extraction prerequisite."),
          }, status=HTTPStatus.CONFLICT)
          return

        secoc_key = TSKExtractor.hack()
        verification = verify_candidate_from_oracle(bytes.fromhex(secoc_key))
        if verification.get("status") != "found":
          self._send_json({
            "ok": False,
            "status": "candidate_unverified",
            "candidate": secoc_key,
            "verification": verification,
            "extraction": dict(TSKExtractor._last_extraction_metadata),
            "message": ("RAM extraction produced a checksum-valid KEY_4 candidate, but it did not pass " +
                        "the persisted SecOC CAN oracle. The candidate was NOT installed. "
                        + verification.get("message", "")),
          }, status=HTTPStatus.UNPROCESSABLE_ENTITY)
          return
        recovered, profile = persist_verified_recovery(secoc_key, verification, source="ram-extraction")
        self._send_json({
          "ok": True,
          "status": "key_recovered",
          "key": secoc_key,
          "recovered_key": recovered,
          "target_profile": profile,
          "verification": verification,
          "extraction": dict(TSKExtractor._last_extraction_metadata),
          "message": (f"Cryptographically verified key recovered:\n{format_key(secoc_key)}\n\n" +
                      f"{verification['matches']} CAN-oracle matches " +
                      f"(sync {verification['sync']}, protected {verification['protected']}).\n\n" +
                      "The key was NOT installed as SecOCKey. Complete target integration and stationary verification first."),
        })
      except NotAGNOSError:
        self._send_extract_dry_run()
        return
      except Exception as e:
        tb = traceback.format_exc()
        self._send_json({
          "ok": False,
          "message": f"{e}\n\n{tb}\n\n{PING_REPORT}",
        }, status=HTTPStatus.INTERNAL_SERVER_ERROR)
      finally:
        TSKExtractor._close_panda()
        panda_lock.release()
      return

    if path == "/api/match":
      if not matcher_lock.acquire(blocking=False):
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "Key finder is already running.",
        }, status=HTTPStatus.CONFLICT)
        return

      try:
        from tsk.lib.matcher import run as run_matcher
        result = run_matcher()
        if result["status"] == "found":
          recovered, profile = persist_verified_recovery(result["key"], result, source="dataflash-match")
          detail = (
            f"Found at {result['address']} — {result['matches']} matches " +
            f"(sync {result['sync']}, protected {result['protected']})."
          )
          message = (
            f"Cryptographically verified key recovered:\n{format_key(result['key'])}\n\n" +
            f"{detail}\n\n" +
            "The candidate has been stored privately as recovered evidence, not installed as SecOCKey. " +
            "Current-openpilot ID matches are reported as compatibility evidence only."
          )
          self._send_json({
            "ok": True,
            "status": "key_recovered",
            "key": result["key"],
            "recovered_key": recovered,
            "target_profile": profile,
            "protected_by_id": result.get("protected_by_id", {}),
            "protected_by_bus": result.get("protected_by_bus", {}),
            "protected_by_stream": result.get("protected_by_stream", {}),
            "domain": result.get("domain", ""),
            "legacy_lateral_ready": result.get("legacy_lateral_ready", False),
            "legacy_lateral_matches_by_id": result.get("legacy_lateral_matches_by_id", {}),
            "legacy_longitudinal_ready": result.get("legacy_longitudinal_ready", False),
            "legacy_longitudinal_matches_by_id": result.get("legacy_longitudinal_matches_by_id", {}),
            "alternate_verified": result.get("alternate_verified", []),
            "message": message,
            **RebootManager.key_status_payload(),
          })
        else:
          # Forward the matcher's debug fields; index.html builds the not-found
          # debug block from these plus the dump/oracle counts it already polls.
          self._send_json({
            "ok": False,
            "status": result["status"],
            "message": result["message"],
            "matches": result["matches"],
            "sync": result["sync"],
            "protected": result["protected"],
            "protected_by_id": result.get("protected_by_id", {}),
            "protected_by_bus": result.get("protected_by_bus", {}),
            "domain": result.get("domain", ""),
            "legacy_lateral_ready": result.get("legacy_lateral_ready", False),
            "legacy_lateral_matches_by_id": result.get("legacy_lateral_matches_by_id", {}),
            "legacy_lateral_missing": result.get("legacy_lateral_missing", []),
            "legacy_longitudinal_ready": result.get("legacy_longitudinal_ready", False),
            "legacy_longitudinal_matches_by_id": result.get("legacy_longitudinal_matches_by_id", {}),
            "legacy_longitudinal_missing": result.get("legacy_longitudinal_missing", []),
            "alternate_verified": result.get("alternate_verified", []),
            "address": result["address"],
            "offset": result["offset"],
            "windows_scanned": result["windows_scanned"],
            "windows_eligible": result.get("windows_eligible", result["windows_scanned"]),
            "coverage_known": result.get("coverage_known", False),
            "survivors": result["survivors"],
            "malformed": result["malformed"],
            "dump_partial": result["dump_partial"],
          })
      except Exception as e:
        tb = traceback.format_exc()
        self._send_json({
          "ok": False,
          "status": "error",
          "message": f"{e}\n\n{tb}\n\n{PING_REPORT}",
          "traceback": tb,
        }, status=HTTPStatus.INTERNAL_SERVER_ERROR)
      finally:
        matcher_lock.release()
      return

    if path == "/api/refresh-target-profile":
      try:
        if not public_recovered_key_status().get("recovered"):
          self._send_json({"ok": False, "status": "no_recovered_key",
                           "message": "Recover a cryptographically verified key before refreshing the target profile."},
                          status=HTTPStatus.CONFLICT)
          return
        with ident_lock:
          identity_snapshot = dict(ident_state)
          identity_snapshot["identity"] = [dict(row) for row in ident_state.get("identity", [])]
        profile = refresh_target_profile_from_recovered(identity_snapshot, oracle_path=can_oracle_path())
        self._send_json({"ok": True, "target_profile": profile})
      except Exception as e:
        self._send_json({"ok": False, "status": "error", "message": str(e),
                         "traceback": traceback.format_exc()}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
      return

    if path == "/api/target-profile-manifest":
      try:
        request = self._read_json_body()
        with ident_lock:
          identity_snapshot = dict(ident_state)
          identity_snapshot["identity"] = [dict(row) for row in ident_state.get("identity", [])]
        manifest, profile = save_integration_and_refresh(
          identity_snapshot,
          str(request.get("profile_id", "")),
          request.get("fields", {}),
          request.get("evidence", {}),
          reviewed=bool(request.get("reviewed", False)),
        )
        self._send_json({"ok": True, "manifest": manifest, "target_profile": profile})
      except ValueError as e:
        self._send_json({"ok": False, "status": "invalid_manifest", "message": str(e)},
                        status=HTTPStatus.CONFLICT)
      except Exception as e:
        self._send_json({"ok": False, "status": "error", "message": str(e),
                         "traceback": traceback.format_exc()}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
      return

    if path == "/api/stationary-verify":
      try:
        request = self._read_json_body()
        with ident_lock:
          identity_snapshot = dict(ident_state)
          identity_snapshot["identity"] = [dict(row) for row in ident_state.get("identity", [])]
        result, profile = verify_stationary_and_refresh(
          identity_snapshot,
          request.get("evidence", {}),
          capture_path=str(request.get("capture_path", "")),
        )
        status = HTTPStatus.OK if result.get("status") == "passed" else HTTPStatus.UNPROCESSABLE_ENTITY
        self._send_json({"ok": result.get("status") == "passed", "result": result,
                         "target_profile": profile}, status=status)
      except ValueError as e:
        self._send_json({"ok": False, "status": "invalid_stationary_evidence", "message": str(e)},
                        status=HTTPStatus.CONFLICT)
      except Exception as e:
        self._send_json({"ok": False, "status": "error", "message": str(e),
                         "traceback": traceback.format_exc()}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
      return

    if path == "/api/install-recovered-key":
      try:
        recovered = public_recovered_key_status()
        profile = public_target_profile_status()
        readiness = profile.get("readiness", {})
        profile_key = profile.get("recovered_key", {})
        if not recovered.get("recovered"):
          self._send_json({
            "ok": False, "status": "no_recovered_key",
            "message": "No cryptographically recovered key is stored. Recover and verify a target key first.",
          }, status=HTTPStatus.CONFLICT)
          return
        if profile_key.get("key_sha256_prefix") != recovered.get("key_sha256_prefix"):
          self._send_json({
            "ok": False, "status": "profile_key_mismatch",
            "message": "The target profile is not bound to the currently recovered key. Rebuild/verify the profile before installation.",
            "target_profile": profile,
          }, status=HTTPStatus.CONFLICT)
          return
        if not readiness.get("operational_install_allowed"):
          unresolved = profile.get("unresolved", [])
          self._send_json({
            "ok": False, "status": "integration_not_verified",
            "message": ("Recovered key is intentionally not installable yet. " +
                        "Target integration and profile-bound stationary verification must pass first."),
            "unresolved": unresolved,
            "target_profile": profile,
          }, status=HTTPStatus.CONFLICT)
          return
        key = recovered_key_hex()
        if key is None:
          raise RuntimeError("recovered-key record became unreadable")
        KeyFileManager().install_key(key)
        self._send_json({
          "ok": True,
          "status": "installed",
          "message": "Profile-verified recovered key installed as SecOCKey.",
          "target_profile": profile,
          **RebootManager.key_status_payload(),
        })
      except Exception as e:
        self._send_json({
          "ok": False, "status": "error", "message": str(e),
          "traceback": traceback.format_exc(),
        }, status=HTTPStatus.INTERNAL_SERVER_ERROR)
      return

    if path == "/api/uninstall":
      try:
        key_manager = KeyFileManager()
        key_was_installed = key_manager.installed_key is not None
        key_manager.uninstall_key()
        self._send_json({
          "ok": True,
          "title": "Key removed" if key_was_installed else "Key not installed",
          "message": "Installed key removed." if key_was_installed else "Nothing to remove.",
          **RebootManager.key_status_payload(),
        })
      except Exception as e:
        self._send_json({
          "ok": False,
          "error": "unexpected",
          "title": "Unexpected error",
          "message": str(e),
          "traceback": traceback.format_exc(),
          **RebootManager.key_status_payload(),
        }, status=HTTPStatus.INTERNAL_SERVER_ERROR)
      return

    if path == "/api/reboot":
      try:
        request = self._read_json_body()
        status, payload = run_reboot_action(str(request.get("action", "")))
        self._send_json(payload, status=status)
      except Exception as e:
        self._send_json({
          "ok": False,
          "error": "unexpected",
          "title": "Unexpected error",
          "message": str(e),
          "traceback": traceback.format_exc(),
          **RebootManager.key_status_payload(),
        }, status=HTTPStatus.INTERNAL_SERVER_ERROR)
      return

    if path == "/api/ephemeral-runtime-package":
      try:
        request = self._read_json_body()
        with ident_lock:
          app_sw = _identity_value([dict(row) for row in ident_state.get("identity", [])], "app_sw_id")
        if not app_sw:
          self._send_json({
            "ok": False, "status": "identity_required",
            "message": "Identify the EPS F181 before importing a SHA-bound runtime package.",
          }, status=HTTPStatus.CONFLICT)
          return
        status = import_runtime_package_json(request, expected_f181=app_sw)
        self._send_json({"ok": True, "status": "imported", "runtime": status})
      except EphemeralRuntimeError as e:
        self._send_json({"ok": False, "status": "invalid_runtime_package", "message": str(e)},
                        status=HTTPStatus.CONFLICT)
      except Exception as e:
        self._send_json({"ok": False, "status": "error", "message": str(e),
                         "traceback": traceback.format_exc()}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
      return

    if path == "/api/ephemeral-canary":
      request = self._read_json_body()
      if not bool(request.get("bench_isolated", False)):
        self._send_json({
          "ok": False, "status": "bench_ack_required",
          "message": "Inert canary execution requires explicit isolated-bench acknowledgement. No programming request was sent.",
        }, status=HTTPStatus.CONFLICT)
        return
      with ident_lock:
        app_sw = _identity_value([dict(row) for row in ident_state.get("identity", [])], "app_sw_id")
      runtime = public_runtime_status(app_sw) if app_sw else public_runtime_status("")
      if not runtime.get("live_canary_ready"):
        self._send_json({
          "ok": False, "status": "runtime_not_ready", "runtime": runtime,
          "message": runtime.get("message", "Audited inert runtime is not ready for this F181."),
        }, status=HTTPStatus.CONFLICT)
        return
      if not start_ephemeral_canary_job(app_sw, bench_isolated=True):
        self._send_json({
          "ok": False, "status": "running",
          "message": "The inert canary could not start; another panda operation may be in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running", "runtime": runtime})
      return

    if path == "/api/can-collect":
      if not start_can_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A CAN collection or another panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/dataflash-dump":
      request = self._read_json_body()
      use_recovery_payload = bool(request.get("use_recovery_payload", False))
      selected_fixture_sha = DATAFLASH_AUTORESET_PAYLOAD_SHA256 if use_recovery_payload else DATAFLASH_PAYLOAD_SHA256
      with ident_lock:
        geometry_gate = ram_exec_geometry_status(
          [dict(row) for row in ident_state.get("identity", [])], fixture_sha256=selected_fixture_sha
        )
      if not geometry_gate["ready"]:
        self._send_json({
          "ok": False,
          "status": "ram_exec_geometry_required",
          "ram_exec_geometry": geometry_gate,
          "message": geometry_gate["message"] + " No programming, SecurityAccess, DID write, or payload upload was started.",
        }, status=HTTPStatus.CONFLICT)
        return
      if not geometry_gate.get("dataflash_fixture_ready"):
        self._send_json({
          "ok": False,
          "status": "bootstrap_fixture_required",
          "ram_exec_geometry": geometry_gate,
          "message": (geometry_gate["message"] +
                      " The selected DataFlash payload was not sent; exact fixture acceptance is independent from shared boot geometry."),
        }, status=HTTPStatus.CONFLICT)
        return
      if not start_dataflash_job(use_recovery_payload=use_recovery_payload):
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A DataFlash dump or another panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running",
                       "payload_variant": "auto-reset-experimental" if use_recovery_payload else "standard"})
      return

    if path == "/api/can-sniff":
      if not start_sniff_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/prog-probe":
      if not start_probe_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/dataflash-diag":
      request = self._read_json_body()
      allow_cross_calibration_send_key = bool(request.get("allow_cross_calibration_send_key", False))
      if not start_diag_job(allow_cross_calibration_send_key=allow_cross_calibration_send_key):
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running", "send_key_armed": allow_cross_calibration_send_key})
      return

    if path == "/api/read-mem":
      if not start_readmem_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/xcp-observer":
      request = self._read_json_body()
      profile = str(request.get("profile", "actuation-discriminator"))
      if profile not in XCP_PROFILES:
        self._send_json({
          "ok": False,
          "status": "invalid_profile",
          "message": f"Unknown XCP observation profile: {profile}",
          "profiles": sorted(XCP_PROFILES),
        }, status=HTTPStatus.BAD_REQUEST)
        return
      if not start_xcp_job(profile):
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running", "profile": profile})
      return

    if path == "/api/ident-map":
      if not start_ident_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/reset-probe":
      if not start_reset_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/level3-probe":
      if not start_level3_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/uds-sweep":
      if not start_sweep_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/ready-capture":
      if not start_ready_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running", "mode": "passive"})
      return

    if path == "/api/ready-diff":
      if not start_ready_diff_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running", "mode": "active_diff"})
      return

    if path == "/api/preamble-probe":
      if not start_preamble_job():
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running"})
      return

    if path == "/api/sendkey-probe":
      request = self._read_json_body()
      allow_cross_calibration = bool(request.get("allow_cross_calibration", False))
      if not start_sendkey_job(allow_cross_calibration=allow_cross_calibration):
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A panda operation is already in progress.",
        }, status=HTTPStatus.CONFLICT)
        return
      self._send_json({"ok": True, "status": "running", "armed": allow_cross_calibration})
      return

    if path == "/api/clear-cache":
      with can_lock:
        can_running = can_state["status"] == "running"
      with df_lock:
        df_running = df_state["status"] == "running"
      if can_running or df_running:
        self._send_json({
          "ok": False,
          "status": "running",
          "message": "A collection or dump is in progress. Wait for it to finish, then clear.",
        }, status=HTTPStatus.CONFLICT)
        return
      clear_can()
      clear_dataflash()
      invalidate_target_profile()
      self._send_json({
        "ok": True,
        "message": (
          "Captured CAN/DataFlash evidence and derived target-profile gates cleared. " +
          "The privately recovered key and any installed SecOCKey were preserved."
        ),
      })
      return

    self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

  def _handle_request(self, send_body: bool) -> None:
    path = urlparse(self.path).path

    if path == "/api/evidence-bundle":
      try:
        bundle = create_evidence_bundle(operation_states_snapshot())
        self._send_download(bundle, "application/gzip", send_body=send_body)
      except Exception as e:
        self._send_json({"ok": False, "message": str(e), "traceback": traceback.format_exc()},
                        status=HTTPStatus.INTERNAL_SERVER_ERROR, send_body=send_body)
      return

    if path == "/api/health":
      # Keep health cheap and deterministic off-device. Hostname/address discovery can
      # block for seconds on macOS when mDNS/DNS is unhappy and is not needed by the
      # workstation health check. AGNOS still reports the reachable device addresses.
      agnos = is_agnos()
      addresses = get_ipv4_addresses() if agnos else []
      self._send_json({
        "status": "ok",
        "service": "tsk_web",
        "host": HOST,
        "port": PORT,
        "url": f"http://{addresses[0]}:{PORT}" if addresses else None,
        "addresses": addresses,
        "asset_dir": str(ASSET_DIR),
        "dry_run": not agnos,
        "is_agnos": agnos,
      }, send_body=send_body)
      return

    if path == "/api/status":
      self._send_json(RebootManager.key_status_payload(), send_body=send_body)
      return

    if path == "/api/dashboard":
      self._send_json(dashboard_payload(), send_body=send_body)
      return

    if path == "/api/target-profile":
      self._send_json({
        "target_profile": public_target_profile_status(),
        "integration_manifest": integration_manifest_template(),
      }, send_body=send_body)
      return

    if path == "/api/stationary-plan":
      self._send_json(stationary_plan(), send_body=send_body)
      return

    if path == "/api/can-status":
      with can_lock:
        payload = dict(can_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/dataflash-status":
      with df_lock:
        payload = dict(df_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/can-sniff-status":
      with sniff_lock:
        payload = dict(sniff_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/dataflash-diag-status":
      with diag_lock:
        payload = dict(diag_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/prog-probe-status":
      with probe_lock:
        payload = dict(probe_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/read-mem-status":
      with readmem_lock:
        payload = dict(readmem_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/ephemeral-runtime-status":
      with ident_lock:
        app_sw = _identity_value([dict(row) for row in ident_state.get("identity", [])], "app_sw_id")
      with ephemeral_lock:
        job = dict(ephemeral_state)
      self._send_json({
        "runtime": public_runtime_status(app_sw) if app_sw else public_runtime_status(""),
        "job": job,
      }, send_body=send_body)
      return

    if path == "/api/xcp-observer-status":
      with xcp_lock:
        payload = dict(xcp_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/ident-map-status":
      with ident_lock:
        payload = dict(ident_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/reset-probe-status":
      with reset_lock:
        payload = dict(reset_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/level3-status":
      with level3_lock:
        payload = dict(level3_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/sendkey-status":
      with sendkey_lock:
        payload = dict(sendkey_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/preamble-status":
      with preamble_lock:
        payload = dict(preamble_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/uds-sweep-status":
      with sweep_lock:
        payload = dict(sweep_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/ready-capture-status":
      with ready_lock:
        payload = dict(ready_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/ready-diff-status":
      with ready_diff_lock:
        payload = dict(ready_diff_state)
      self._send_json(payload, send_body=send_body)
      return

    if path == "/api/reboot":
      try:
        self._send_json(get_reboot_actions_payload(), send_body=send_body)
      except Exception as e:
        self._send_json({
          "ok": False,
          "error": "unexpected",
          "title": "Unexpected error",
          "message": str(e),
          "traceback": traceback.format_exc(),
        }, status=HTTPStatus.INTERNAL_SERVER_ERROR, send_body=send_body)
      return

    if path == "/favicon.ico":
      self.send_response(HTTPStatus.NO_CONTENT)
      self.end_headers()
      return

    asset = resolve_asset(path)
    if asset is not None:
      self._send_bytes(HTTPStatus.OK, content_type_for(asset), asset.read_bytes(), send_body=send_body)
      return

    self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND, send_body=send_body)

  def _send_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK, send_body: bool = True) -> None:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    self._send_bytes(status, "application/json; charset=utf-8", body, send_body=send_body)

  def _read_json_body(self) -> dict:
    length = int(self.headers.get("Content-Length", "0") or "0")
    if length <= 0:
      return {}
    raw_body = self.rfile.read(length)
    if not raw_body:
      return {}
    return json.loads(raw_body.decode("utf-8"))

  def _send_download(self, path: Path, content_type: str, send_body: bool = True) -> None:
    self.send_response(HTTPStatus.OK)
    self.send_header("Content-Type", content_type)
    self.send_header("Content-Length", str(path.stat().st_size))
    self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
    self.send_header("Cache-Control", "no-store")
    self.end_headers()
    if send_body:
      with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
          self.wfile.write(block)

  def _send_bytes(self, status: HTTPStatus, content_type: str, body: bytes, send_body: bool = True) -> None:
    self.send_response(status)
    self.send_header("Content-Type", content_type)
    self.send_header("Content-Length", str(len(body)))
    self.send_header("Cache-Control", "no-store")
    self.end_headers()
    if send_body:
      self.wfile.write(body)

  def log_message(self, fmt: str, *args: object) -> None:
    return


class TSKWebServer(ThreadingHTTPServer):
  allow_reuse_address = True
  daemon_threads = True


def main() -> None:
  rehydrate_dataflash_state()
  rehydrate_can_state()
  update_offroad_alert()
  threading.Thread(target=offroad_alert_loop, name="tsk_offroad_alert", daemon=True).start()

  server = TSKWebServer((HOST, PORT), TSKWebHandler)
  print(f"TSK Manager Web listening on http://{HOST}:{PORT}", flush=True)
  for ip in get_ipv4_addresses():
    print(f"TSK Manager Web detected address: http://{ip}:{PORT}", flush=True)

  try:
    server.serve_forever()
  except KeyboardInterrupt:
    pass
  finally:
    server.server_close()


if __name__ == "__main__":
  main()
