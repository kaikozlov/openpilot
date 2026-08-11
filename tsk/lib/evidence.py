#!/usr/bin/env python3
"""Append-only operation logging and portable field-session evidence bundles."""
import hashlib
import json
import os
import subprocess
import tarfile
import time
from datetime import datetime, UTC
from pathlib import Path
from uuid import uuid4

from tsk.lib.env import (
  CACHE_DIR, DATAFLASH_AUTORESET_PAYLOAD_PATH, DATAFLASH_PAYLOAD_PATH, OPENPILOT_DIR, PAYLOAD_PATH,
)

EVIDENCE_ROOT = Path(CACHE_DIR) / "tsk"
BUNDLE_DIR = EVIDENCE_ROOT / "evidence"
MANIFEST_PATH = EVIDENCE_ROOT / "session-manifest.json"
OPERATION_LOG_PATH = EVIDENCE_ROOT / "operations.ndjson"


def _utc_now() -> str:
  return datetime.now(UTC).isoformat()


def sha256_file(path: Path) -> str:
  digest = hashlib.sha256()
  with path.open("rb") as fh:
    for block in iter(lambda: fh.read(1024 * 1024), b""):
      digest.update(block)
  return digest.hexdigest()


def _git_value(*args: str) -> str:
  try:
    return subprocess.check_output(["git", "-C", OPENPILOT_DIR, *args],
                                   encoding="utf-8", stderr=subprocess.DEVNULL,
                                   timeout=3).strip()
  except Exception:
    return "unknown"


def _device_id_hash() -> str:
  try:
    value = Path("/persist/comma/dongle_id").read_text(encoding="utf-8").strip()
  except OSError:
    return "unavailable"
  return hashlib.sha256(value.encode()).hexdigest()[:16]


def record_operation(operation: str, **fields) -> None:
  """Append one server-side operation invocation without truncating prior runs."""
  EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
  record = {
    "event": "operation_invoked",
    "operation": operation,
    "time_utc": _utc_now(),
    "t_mono_ns": time.monotonic_ns(),
  }
  record.update(fields)
  with OPERATION_LOG_PATH.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(record, sort_keys=True) + "\n")
    fh.flush()
    os.fsync(fh.fileno())


def _candidate_files() -> list[Path]:
  if not EVIDENCE_ROOT.exists():
    return []
  files = []
  for path in EVIDENCE_ROOT.rglob("*"):
    if not path.is_file() or BUNDLE_DIR in path.parents:
      continue
    files.append(path)
  return sorted(files)


def build_manifest(operation_states: dict | None = None) -> dict:
  payloads = []
  for label, raw_path in (("ram_dump_payload", PAYLOAD_PATH),
                          ("dataflash_dump_payload", DATAFLASH_PAYLOAD_PATH),
                          ("dataflash_autoreset_payload", DATAFLASH_AUTORESET_PAYLOAD_PATH)):
    path = Path(raw_path)
    payloads.append({
      "name": label,
      "path": str(path),
      "size": path.stat().st_size if path.exists() else None,
      "sha256": sha256_file(path) if path.exists() else None,
    })

  files = []
  for path in _candidate_files():
    try:
      relative = path.relative_to(EVIDENCE_ROOT)
      files.append({
        "path": str(relative),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
      })
    except OSError:
      continue

  try:
    agnos_version = Path("/VERSION").read_text(encoding="utf-8").strip()
  except OSError:
    agnos_version = "unavailable"

  return {
    "schema_version": 1,
    "created_utc": _utc_now(),
    "created_mono_ns": time.monotonic_ns(),
    "openpilot": {
      "commit": _git_value("rev-parse", "HEAD"),
      "branch": _git_value("branch", "--show-current"),
      "status": _git_value("status", "--short"),
    },
    "device": {
      "agnos_version": agnos_version,
      "dongle_id_sha256_prefix": _device_id_hash(),
    },
    "payloads": payloads,
    "operation_states": operation_states or {},
    "files": files,
  }


def create_evidence_bundle(operation_states: dict | None = None) -> Path:
  """Write the current manifest and a gzipped tar archive of all TSK evidence."""
  EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
  record_operation("evidence_bundle_requested")
  BUNDLE_DIR.mkdir(parents=True, exist_ok=True)
  manifest = build_manifest(operation_states)
  temporary = MANIFEST_PATH.with_suffix(".json.tmp")
  temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
  os.replace(temporary, MANIFEST_PATH)

  stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
  bundle_path = BUNDLE_DIR / f"tsk-evidence-{stamp}-{uuid4().hex[:8]}.tar.gz"
  with tarfile.open(bundle_path, "w:gz") as archive:
    for path in _candidate_files():
      try:
        archive.add(path, arcname=str(Path("tsk-evidence") / path.relative_to(EVIDENCE_ROOT)),
                    recursive=False)
      except OSError:
        continue
    launch_log = Path("/tmp/launch_log")
    if launch_log.is_file():
      archive.add(launch_log, arcname="tsk-evidence/logs/launch_log", recursive=False)

  record_operation("evidence_bundle_created", path=str(bundle_path),
                   size=bundle_path.stat().st_size, sha256=sha256_file(bundle_path))
  return bundle_path


def inspect_bundle(path: Path) -> set[str]:
  """Return member names; used by local tests without extracting the archive."""
  with tarfile.open(path, "r:gz") as archive:
    return set(archive.getnames())
