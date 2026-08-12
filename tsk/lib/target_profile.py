#!/usr/bin/env python3
"""Build and persist an evidence-bound TSK target profile.

A target profile records what was actually observed on one EPS/route and what a
recovered key actually authenticates. It deliberately does *not* manufacture an
opendbc platform definition from model-year assumptions.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, UTC
from pathlib import Path

from tsk.lib.env import CACHE_DIR, CAN_ORACLE_PATH
from tsk.lib.recovered_key import public_recovered_key_status
from tsk.lib.secoc_discovery import load_oracle_discovery
from tsk.lib.secoc_profile import (
  CURRENT_OPENPILOT_LATERAL_PROTECTED_ADDRS,
  CURRENT_OPENPILOT_LONGITUDINAL_PROTECTED_ADDRS,
  SYNC_ADDR,
)

TARGET_PROFILE_PATH = Path(CACHE_DIR) / "tsk" / "target-profile.json"
STATIONARY_RESULT_PATH = Path(CACHE_DIR) / "tsk" / "stationary-verification.json"
INTEGRATION_MANIFEST_PATH = Path(CACHE_DIR) / "tsk" / "openpilot-integration.json"

# These cannot be inferred safely from a SecOC key or a Sienna-family DBC. They must
# be established from target evidence before operational integration is considered
# complete.
REQUIRED_INTEGRATION_FIELDS = (
  "platform_name",
  "dbc_pt",
  "safety_flags",
  "steer_control_type",
  "eps_scale",
  "lateral_command_role",
  "lateral_status_feedback",
  "longitudinal_topology",
)


def _sha256(path: Path) -> str:
  digest = hashlib.sha256()
  with path.open("rb") as fh:
    for block in iter(lambda: fh.read(1024 * 1024), b""):
      digest.update(block)
  return digest.hexdigest()


def _identity_value(identity_state: dict, name: str) -> str:
  for entry in identity_state.get("identity", []):
    if entry.get("name") == name:
      return str(entry.get("ascii", "")).strip(".\x00 ")
  return ""


def _json_file(path: Path) -> dict | None:
  try:
    value = json.loads(path.read_text(encoding="utf-8"))
  except (OSError, json.JSONDecodeError):
    return None
  return value if isinstance(value, dict) else None


def _integration_status() -> dict:
  manifest = _json_file(INTEGRATION_MANIFEST_PATH) or {}
  fields = manifest.get("fields", {}) if isinstance(manifest.get("fields", {}), dict) else {}
  missing = [name for name in REQUIRED_INTEGRATION_FIELDS if fields.get(name) in (None, "", [], {})]
  return {
    "present": bool(manifest),
    "ready": bool(manifest) and not missing and bool(manifest.get("reviewed")),
    "reviewed": bool(manifest.get("reviewed")),
    "missing_fields": missing,
    "fields": fields,
  }


def _stationary_status(profile_id: str) -> dict:
  result = _json_file(STATIONARY_RESULT_PATH) or {}
  bound = result.get("profile_id") == profile_id
  passed = bound and result.get("status") == "passed"
  return {
    "present": bool(result),
    "profile_bound": bound,
    "status": result.get("status", "not_run") if bound else "not_run",
    "passed": passed,
    "checks": list(result.get("checks", [])) if bound else [],
  }


def _write_atomic(path: Path, value: dict) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  fd, temporary_name = tempfile.mkstemp(prefix=f".{path.stem}.", suffix=".json", dir=path.parent)
  try:
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
      json.dump(value, fh, indent=2, sort_keys=True)
      fh.write("\n")
      fh.flush()
      os.fsync(fh.fileno())
    os.replace(temporary_name, path)
  except BaseException:
    try:
      os.unlink(temporary_name)
    except OSError:
      pass
    raise


def build_target_profile(identity_state: dict, *, verification: dict | None = None,
                         oracle_path: Path | None = None) -> dict:
  oracle = Path(oracle_path or CAN_ORACLE_PATH)
  discovery = load_oracle_discovery(oracle)
  verification = verification or {}
  verified_streams = {
    str(key): int(value) for key, value in verification.get("protected_by_stream", {}).items()
  }
  verified_by_id = {
    str(key).lower(): int(value) for key, value in verification.get("protected_by_id", {}).items()
  }

  streams = []
  for row in discovery["streams"]:
    stream_key = f"{row['bus']}:0x{int(row['addr_int']):03x}"
    addr_key = f"0x{int(row['addr_int']):03x}"
    stream = dict(row)
    stream["verified_matches"] = int(verified_streams.get(stream_key, 0))
    # Older verification records lacked per-bus counts. Keep a conservative ID-level
    # hint separate rather than falsely attributing those matches to this bus.
    stream["verified_matches_id_aggregate"] = int(verified_by_id.get(addr_key, 0))
    stream["cryptographically_verified"] = stream["verified_matches"] >= 2
    streams.append(stream)

  route = {
    "tx": identity_state.get("eps_tx", ""),
    "rx": identity_state.get("eps_rx", ""),
    "tx_bus": int(identity_state.get("eps_bus", -1)),
    "rx_bus": int(identity_state.get("eps_rx_bus", -1)),
    "elm327_param": int(identity_state.get("elm327_param", -1)),
    "semantic_path": identity_state.get("semantic_path", ""),
  }
  identity = {
    "app_sw_id": _identity_value(identity_state, "app_sw_id"),
    "spare_part_no": _identity_value(identity_state, "spare_part_no"),
    "ecu_serial": _identity_value(identity_state, "ecu_serial"),
    "panda": identity_state.get("panda", ""),
  }
  stable_identity = {
    "identity": identity,
    "route": route,
    "oracle_sha256": _sha256(oracle),
    "streams": [
      {
        "bus": row["bus"], "addr": row["addr"], "lengths": row["lengths"],
        "structural_candidate": row["structural_candidate"],
        "known_toyota_hypothesis": row["known_toyota_hypothesis"],
      }
      for row in streams
    ],
  }
  profile_id = hashlib.sha256(
    json.dumps(stable_identity, sort_keys=True, separators=(",", ":")).encode()
  ).hexdigest()[:20]

  lateral_matches = {
    f"0x{addr:03x}": int(verified_by_id.get(f"0x{addr:03x}", 0))
    for addr in sorted(CURRENT_OPENPILOT_LATERAL_PROTECTED_ADDRS)
  }
  longitudinal_matches = {
    f"0x{addr:03x}": int(verified_by_id.get(f"0x{addr:03x}", 0))
    for addr in sorted(CURRENT_OPENPILOT_LONGITUDINAL_PROTECTED_ADDRS)
  }
  lateral_crypto = all(value >= 2 for value in lateral_matches.values())
  longitudinal_crypto = all(value >= 2 for value in longitudinal_matches.values())
  key_status = public_recovered_key_status()
  integration = _integration_status()
  stationary = _stationary_status(profile_id)
  operational_install_allowed = bool(
    key_status["recovered"] and integration["ready"] and stationary["passed"]
  )

  unresolved = []
  if not identity["app_sw_id"]:
    unresolved.append("exact EPS application software ID")
  if not any(row["structural_candidate"] or row["known_toyota_hypothesis"] for row in streams):
    unresolved.append("classic SecOC protected stream surface")
  if not key_status["recovered"]:
    unresolved.append("cryptographically recovered target key")
  unresolved.extend(f"openpilot integration: {field}" for field in integration["missing_fields"])
  if not stationary["passed"]:
    unresolved.append("profile-bound stationary acceptance/status verification")

  return {
    "schema_version": 1,
    "generated_utc": datetime.now(UTC).isoformat(),
    "profile_id": profile_id,
    "identity": identity,
    "route": route,
    "oracle": {
      "path": str(oracle),
      "sha256": stable_identity["oracle_sha256"],
      "sync_id": f"0x{SYNC_ADDR:03x}",
      "sync_samples": len(discovery["sync_samples"]),
      "sync_buses": sorted({int(sample["bus"]) for sample in discovery["sync_samples"]}),
      "malformed": discovery["malformed"],
    },
    "secoc_streams": streams,
    "discovery": {
      "unknown_structural_candidates": discovery["unknown_structural_candidates"],
      "unknown_scan_streams": discovery["unknown_scan_streams"],
    },
    "recovered_key": key_status,
    "current_openpilot_compatibility": {
      "lateral_crypto_compatible": lateral_crypto,
      "lateral_matches_by_id": lateral_matches,
      "longitudinal_crypto_compatible": longitudinal_crypto,
      "longitudinal_matches_by_id": longitudinal_matches,
      "note": "Compatibility with the current Toyota sender is evidence, not proof that this target should use that platform/DBC/safety profile.",
    },
    "integration": integration,
    "stationary_verification": stationary,
    "readiness": {
      "key_recovered": bool(key_status["recovered"]),
      "target_profile_observed": bool(identity["app_sw_id"] and streams),
      "openpilot_integration_reviewed": bool(integration["ready"]),
      "stationary_acceptance_verified": bool(stationary["passed"]),
      "operational_install_allowed": operational_install_allowed,
    },
    "unresolved": unresolved,
  }


def persist_target_profile(identity_state: dict, *, verification: dict | None = None,
                           oracle_path: Path | None = None) -> dict:
  profile = build_target_profile(identity_state, verification=verification, oracle_path=oracle_path)
  _write_atomic(TARGET_PROFILE_PATH, profile)
  return profile


def load_target_profile() -> dict | None:
  return _json_file(TARGET_PROFILE_PATH)


def public_target_profile_status() -> dict:
  profile = load_target_profile()
  if not profile:
    return {"present": False, "profile_id": "", "readiness": {}, "unresolved": []}
  return {
    "present": True,
    "profile_id": profile.get("profile_id", ""),
    "generated_utc": profile.get("generated_utc", ""),
    "identity": dict(profile.get("identity", {})),
    "route": dict(profile.get("route", {})),
    "discovery": dict(profile.get("discovery", {})),
    "current_openpilot_compatibility": dict(profile.get("current_openpilot_compatibility", {})),
    "integration": dict(profile.get("integration", {})),
    "stationary_verification": dict(profile.get("stationary_verification", {})),
    "readiness": dict(profile.get("readiness", {})),
    "unresolved": list(profile.get("unresolved", [])),
  }
