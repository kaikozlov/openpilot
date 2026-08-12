#!/usr/bin/env python3
"""Profile-bound stationary/bench integration evidence gate.

This module intentionally does not transmit steering commands. It validates a normalized
stationary session artifact produced while exercising a reviewed target-specific probe.
Until that dynamic artifact exists, operational SecOCKey installation remains blocked.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, UTC
from pathlib import Path

from tsk.lib.env import CACHE_DIR
from tsk.lib.target_profile import STATIONARY_RESULT_PATH, load_target_profile, refresh_target_profile_from_recovered

EVIDENCE_ROOT = Path(CACHE_DIR) / "tsk"
MAX_STATIONARY_SPEED_MPS = 0.05


def _hash(path: Path) -> str:
  digest = hashlib.sha256()
  with path.open("rb") as fh:
    for block in iter(lambda: fh.read(1024 * 1024), b""):
      digest.update(block)
  return digest.hexdigest()


def _atomic_write(value: dict) -> None:
  STATIONARY_RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
  fd, temporary_name = tempfile.mkstemp(prefix=".stationary-verification.", suffix=".json",
                                        dir=STATIONARY_RESULT_PATH.parent)
  try:
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
      json.dump(value, fh, indent=2, sort_keys=True)
      fh.write("\n")
      fh.flush()
      os.fsync(fh.fileno())
    os.replace(temporary_name, STATIONARY_RESULT_PATH)
  except BaseException:
    try:
      os.unlink(temporary_name)
    except OSError:
      pass
    raise


def stationary_plan() -> dict:
  profile = load_target_profile()
  if not profile:
    return {"ready": False, "profile_id": "", "blocked": ["target profile has not been generated"]}
  blocked = []
  if not profile.get("readiness", {}).get("key_recovered"):
    blocked.append("target key has not been cryptographically recovered")
  if not profile.get("integration", {}).get("ready"):
    blocked.append("openpilot integration manifest is not reviewed/complete")
  verified_streams = [
    f"{row['bus']}:0x{int(row['addr_int']):03x}"
    for row in profile.get("secoc_streams", []) if row.get("cryptographically_verified")
  ]
  if not verified_streams:
    blocked.append("no profile-bound protected stream has per-bus cryptographic verification")
  return {
    "ready": not blocked,
    "profile_id": profile.get("profile_id", ""),
    "blocked": blocked,
    "verified_command_candidates": verified_streams,
    "required_evidence": {
      "capture_path": "relative path under /cache/tsk to the raw stationary/bench session capture",
      "stationary": {"max_speed_mps": f"<= {MAX_STATIONARY_SPEED_MPS}", "source": "target speed/bench evidence"},
      "command": {"stream": "bus:0xID from verified target streams", "zero_actuation": True,
                  "cryptographically_verified": True, "frames": ">= 1", "source": "normalized probe capture"},
      "status": {"acceptance_observed": True, "feedback": "target-specific EPS/status transition", "source": "normalized probe capture"},
      "faults": {"new_faults": [], "source": "before/after EPS diagnostic or status evidence"},
    },
    "note": "TSK does not synthesize or transmit a target command until target-specific semantics exist. This gate validates the resulting session evidence.",
  }


def _resolve_capture(relative_path: str) -> Path:
  root = EVIDENCE_ROOT.resolve()
  path = (root / relative_path).resolve()
  if path == root or root not in path.parents:
    raise ValueError("stationary capture path must stay under /cache/tsk")
  if not path.is_file():
    raise ValueError("stationary capture file does not exist")
  return path


def verify_stationary_evidence(evidence: dict, *, capture_path: str) -> dict:
  profile = load_target_profile()
  if not profile:
    raise ValueError("target profile has not been generated")
  profile_id = str(evidence.get("profile_id", ""))
  if not profile_id or profile_id != profile.get("profile_id"):
    raise ValueError("stationary evidence is not bound to the current target profile")
  if not profile.get("integration", {}).get("ready"):
    raise ValueError("target integration manifest must be reviewed before stationary verification")

  capture = _resolve_capture(capture_path)
  stationary = evidence.get("stationary", {})
  command = evidence.get("command", {})
  status = evidence.get("status", {})
  faults = evidence.get("faults", {})
  verified_streams = {
    f"{row['bus']}:0x{int(row['addr_int']):03x}"
    for row in profile.get("secoc_streams", []) if row.get("cryptographically_verified")
  }

  checks = [
    {
      "name": "vehicle_stationary",
      "passed": isinstance(stationary.get("max_speed_mps"), (int, float))
                and 0 <= float(stationary["max_speed_mps"]) <= MAX_STATIONARY_SPEED_MPS
                and bool(str(stationary.get("source", "")).strip()),
    },
    {
      "name": "signed_zero_actuation_command",
      "passed": command.get("stream") in verified_streams
                and command.get("zero_actuation") is True
                and command.get("cryptographically_verified") is True
                and int(command.get("frames", 0)) >= 1
                and bool(str(command.get("source", "")).strip()),
    },
    {
      "name": "eps_acceptance_feedback",
      "passed": status.get("acceptance_observed") is True
                and bool(str(status.get("feedback", "")).strip())
                and bool(str(status.get("source", "")).strip()),
    },
    {
      "name": "no_new_fault_latch",
      "passed": faults.get("new_faults") == [] and bool(str(faults.get("source", "")).strip()),
    },
  ]
  passed = all(check["passed"] for check in checks)
  result = {
    "schema_version": 1,
    "verified_utc": datetime.now(UTC).isoformat(),
    "profile_id": profile_id,
    "status": "passed" if passed else "failed",
    "capture": {"path": str(capture.relative_to(EVIDENCE_ROOT.resolve())), "sha256": _hash(capture), "size": capture.stat().st_size},
    "checks": checks,
  }
  _atomic_write(result)
  return result


def verify_and_refresh(identity_state: dict, evidence: dict, *, capture_path: str) -> tuple[dict, dict]:
  result = verify_stationary_evidence(evidence, capture_path=capture_path)
  profile = refresh_target_profile_from_recovered(identity_state)
  return result, profile
