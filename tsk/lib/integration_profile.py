#!/usr/bin/env python3
"""Evidence-backed target integration manifest for openpilot/Toyota SecOC.

The manifest is intentionally target/profile-bound. It records values that must be
known before an opendbc platform can honestly be enabled; this module never invents
those values from a model year or from a recovered SecOC key.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, UTC

from tsk.lib.target_profile import (
  INTEGRATION_MANIFEST_PATH, REQUIRED_INTEGRATION_FIELDS, load_target_profile,
  refresh_target_profile_from_recovered,
)

FIELD_GUIDANCE = {
  "platform_name": "Exact opendbc platform/fingerprint identity supported by target evidence.",
  "dbc_pt": "Exact powertrain/SecOC DBC selected for this target; no family guess.",
  "safety_flags": "Toyota panda safety flags/parameters justified by the target topology and control mode.",
  "steer_control_type": "torque or angle, established from the target command/status behavior.",
  "eps_scale": "EPS torque scaling/steering calibration required by CarState/CarController.",
  "lateral_command_role": "Exact protected steering command ID(s), format, bus and semantic role.",
  "lateral_status_feedback": "Exact EPS/status feedback used to prove command acceptance/fault state.",
  "longitudinal_topology": "Stock/openpilot longitudinal ownership, protected command ID(s), and radar/camera topology.",
}


def _atomic_write(value: dict) -> None:
  INTEGRATION_MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
  fd, temporary_name = tempfile.mkstemp(prefix=".openpilot-integration.", suffix=".json",
                                        dir=INTEGRATION_MANIFEST_PATH.parent)
  try:
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
      json.dump(value, fh, indent=2, sort_keys=True)
      fh.write("\n")
      fh.flush()
      os.fsync(fh.fileno())
    os.replace(temporary_name, INTEGRATION_MANIFEST_PATH)
  except BaseException:
    try:
      os.unlink(temporary_name)
    except OSError:
      pass
    raise


def load_manifest() -> dict | None:
  try:
    value = json.loads(INTEGRATION_MANIFEST_PATH.read_text(encoding="utf-8"))
  except (OSError, json.JSONDecodeError):
    return None
  return value if isinstance(value, dict) else None


def manifest_template() -> dict:
  profile = load_target_profile()
  current = load_manifest() or {}
  profile_id = str(profile.get("profile_id", "")) if profile else ""
  bound = bool(profile_id and current.get("profile_id") == profile_id)
  fields = dict(current.get("fields", {})) if bound else {}
  evidence = dict(current.get("evidence", {})) if bound else {}
  return {
    "profile_present": bool(profile),
    "profile_id": profile_id,
    "reviewed": bool(current.get("reviewed")) if bound else False,
    "required_fields": [
      {
        "name": name,
        "value": fields.get(name, ""),
        "evidence": evidence.get(name, ""),
        "guidance": FIELD_GUIDANCE[name],
      }
      for name in REQUIRED_INTEGRATION_FIELDS
    ],
    "note": "Every value requires an evidence source. Completing this manifest does not install a key; stationary verification remains separate.",
  }


def save_manifest(profile_id: str, fields: dict, evidence: dict, *, reviewed: bool) -> dict:
  profile = load_target_profile()
  if not profile or profile.get("profile_id") != profile_id:
    raise ValueError("integration manifest profile_id does not match the current target profile")
  if not isinstance(fields, dict) or not isinstance(evidence, dict):
    raise ValueError("fields and evidence must be objects")
  unknown = (set(fields) | set(evidence)) - set(REQUIRED_INTEGRATION_FIELDS)
  if unknown:
    raise ValueError(f"unknown integration field(s): {', '.join(sorted(unknown))}")

  normalized_fields = {name: fields.get(name, "") for name in REQUIRED_INTEGRATION_FIELDS}
  normalized_evidence = {name: str(evidence.get(name, "")).strip() for name in REQUIRED_INTEGRATION_FIELDS}
  missing = [name for name, value in normalized_fields.items() if value in (None, "", [], {})]
  missing_evidence = [name for name, value in normalized_evidence.items() if not value]
  if reviewed and (missing or missing_evidence):
    details = []
    if missing:
      details.append("missing values: " + ", ".join(missing))
    if missing_evidence:
      details.append("missing evidence: " + ", ".join(missing_evidence))
    raise ValueError("reviewed integration manifest is incomplete (" + "; ".join(details) + ")")

  manifest = {
    "schema_version": 1,
    "updated_utc": datetime.now(UTC).isoformat(),
    "profile_id": profile_id,
    "reviewed": bool(reviewed),
    "fields": normalized_fields,
    "evidence": normalized_evidence,
  }
  _atomic_write(manifest)
  return manifest


def save_and_refresh(identity_state: dict, profile_id: str, fields: dict, evidence: dict,
                     *, reviewed: bool) -> tuple[dict, dict]:
  manifest = save_manifest(profile_id, fields, evidence, reviewed=reviewed)
  profile = refresh_target_profile_from_recovered(identity_state)
  return manifest, profile
