#!/usr/bin/env python3
"""Persist a cryptographically recovered SecOC key without activating openpilot.

Recovery and operational installation are deliberately separate states. A recovered
key lives under TSK's private cache and is not copied to SecOCKey until the target
profile and stationary integration gates have been satisfied.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, UTC
from pathlib import Path

from tsk.lib.env import CACHE_DIR

PRIVATE_DIR = Path(CACHE_DIR) / "tsk" / "private"
RECOVERED_KEY_PATH = PRIVATE_DIR / "recovered-key.json"


def _valid_key_hex(key: str) -> bool:
  if not isinstance(key, str) or len(key) != 32:
    return False
  try:
    bytes.fromhex(key)
  except ValueError:
    return False
  return key == key.lower()


def key_fingerprint(key: str) -> str:
  if not _valid_key_hex(key):
    raise ValueError("SecOC key must be 32 lowercase hex characters")
  return hashlib.sha256(bytes.fromhex(key)).hexdigest()[:16]


def persist_recovered_key(key: str, verification: dict, *, source: str) -> dict:
  if not _valid_key_hex(key):
    raise ValueError("SecOC key must be 32 lowercase hex characters")
  if verification.get("status") != "found":
    raise ValueError("refusing to persist a key that has not passed cryptographic verification")

  PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
  record = {
    "schema_version": 1,
    "recovered_utc": datetime.now(UTC).isoformat(),
    "source": source,
    "key": key,
    "key_sha256_prefix": key_fingerprint(key),
    "verification": {
      "domain": verification.get("domain", "unverified"),
      "matches": int(verification.get("matches", 0)),
      "sync": verification.get("sync", ""),
      "protected": verification.get("protected", ""),
      "protected_by_id": dict(verification.get("protected_by_id", {})),
      "protected_by_bus": dict(verification.get("protected_by_bus", {})),
      "legacy_lateral_ready": bool(verification.get("legacy_lateral_ready", verification.get("control_ready", False))),
      "legacy_lateral_matches_by_id": dict(verification.get("legacy_lateral_matches_by_id", verification.get("control_matches_by_id", {}))),
      "legacy_longitudinal_ready": bool(verification.get("legacy_longitudinal_ready", False)),
      "legacy_longitudinal_matches_by_id": dict(verification.get("legacy_longitudinal_matches_by_id", {})),
    },
  }

  fd, temporary_name = tempfile.mkstemp(prefix=".recovered-key.", suffix=".json", dir=PRIVATE_DIR)
  try:
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
      json.dump(record, fh, indent=2, sort_keys=True)
      fh.write("\n")
      fh.flush()
      os.fsync(fh.fileno())
    os.chmod(temporary_name, 0o600)
    os.replace(temporary_name, RECOVERED_KEY_PATH)
  except BaseException:
    try:
      os.unlink(temporary_name)
    except OSError:
      pass
    raise
  return public_recovered_key_status(record)


def load_recovered_key() -> dict | None:
  try:
    record = json.loads(RECOVERED_KEY_PATH.read_text(encoding="utf-8"))
  except (OSError, json.JSONDecodeError):
    return None
  key = record.get("key", "")
  if not _valid_key_hex(key):
    return None
  if record.get("key_sha256_prefix") != key_fingerprint(key):
    return None
  return record


def public_recovered_key_status(record: dict | None = None) -> dict:
  record = load_recovered_key() if record is None else record
  if record is None:
    return {"recovered": False, "key_sha256_prefix": "", "verification": {}}
  return {
    "recovered": True,
    "recovered_utc": record.get("recovered_utc", ""),
    "source": record.get("source", ""),
    "key_sha256_prefix": record.get("key_sha256_prefix", ""),
    "verification": dict(record.get("verification", {})),
  }


def recovered_key_hex() -> str | None:
  record = load_recovered_key()
  return None if record is None else str(record["key"])


def clear_recovered_key() -> None:
  try:
    RECOVERED_KEY_PATH.unlink()
  except FileNotFoundError:
    pass
