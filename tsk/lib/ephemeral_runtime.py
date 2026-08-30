#!/usr/bin/env python3
"""Validate and bench-test SHA-bound ephemeral scheduler canary packages.

The package model deliberately keeps four independent questions separate:

1. Does this F181 belong to the known authenticated-RAM boot family?
2. Is the selected encrypted 4 KiB bootstrap fixture evidenced for this F181?
3. Does this exact CodeFlash have resolver-proven application-retained R/W/X runtime geometry?
4. Is the post-auth raw-substitution execution primitive verified on this target?

Only the inert scheduler canary is accepted here. TSK intentionally contains no steering
bridge binary or bridge-execution endpoint until the canary transition and reset-to-stock
proof have succeeded on isolated hardware.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from tsk.lib.bootstrap_profile import (
  BOOTSTRAP_TARGETS,
  BOOT_SA_SECRET,
  DID_0201_DEFAULT,
  DID_0202_DEFAULT,
  DOWNLOAD_BASE,
  DOWNLOAD_SIZE,
  EXECUTE_ROUTINE,
  PROFILE_ID,
  SECURITY_ACCESS_DATA_RECORD,
  VERIFY_ROUTINE,
  fixture_is_evidenced,
  public_bootstrap_status,
)
from tsk.lib.diagnostic_route import discover_eps_route_with_routing, rediscover_route, route_fields
from tsk.lib.env import CACHE_DIR, PAYLOAD_PATH, is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.programming import ProgrammingHandoffError, enter_programming_bootloader, uds_client
from tsk.lib.ram_exec_geometry import normalize_f181
from tsk.lib.read_mem import RAM_ID, read_memory_with_id


RUNTIME_SCHEMA = "p1me-ephemeral-runtime-target-manifest-v1"
CANARY_AUDIT_SCHEMA = "p1me-ephemeral-scheduler-canary-audited-build-v2"
CANARY_REVIEW_STATUS = "audited-inert-static-not-bench-validated"
PACKAGE_SCHEMA = "tsk-ephemeral-runtime-package-v1"
VALIDATION_SCHEMA = "tsk-ephemeral-canary-validation-v1"
MAX_IMPORT_JSON = 512 * 1024
MAX_CANARY_SIZE = 4096
MAX_BOOTSTRAP_SIZE = 0x1000
MAX_RAW_CHUNK = 15

RUNTIME_DIR = Path(CACHE_DIR) / "tsk" / "ephemeral-runtime"
IMPORTED_MANIFEST_PATH = RUNTIME_DIR / "target-manifest.json"
IMPORTED_AUDIT_PATH = RUNTIME_DIR / "canary-audit.json"
IMPORTED_CANARY_PATH = RUNTIME_DIR / "canary.bin"
IMPORTED_BOOTSTRAP_PATH = RUNTIME_DIR / "bootstrap-fixture.bin"
IMPORTED_METADATA_PATH = RUNTIME_DIR / "package-metadata.json"
CANARY_VALIDATION_PATH = RUNTIME_DIR / "canary-validation.json"

BUILTIN_DIR = Path(__file__).resolve().parents[1] / "runtime"
BUILTIN_MANIFEST_PATH = BUILTIN_DIR / "target_manifest_8965B4512000.json"
BUILTIN_AUDIT_PATH = BUILTIN_DIR / "audited_canary_8965B4512000.json"
BUILTIN_CANARY_PATH = BUILTIN_DIR / "canary_8965B4512000.bin"
FOREIGN_EVIDENCE_MANIFEST_PATHS = {
  "8965H1202000": BUILTIN_DIR / "target_manifest_8965H1202000.json",
  "8965F1208000": BUILTIN_DIR / "target_manifest_8965F1208000.json",
}

# The only live built-in runtime package today is the analyzed single-CPU, old-stack
# B4512000 target. Protocol builders deliberately support both observed Denso bootstrap
# dialect axes, but live execution remains pinned to these reviewed values.
BUILTIN_RUNTIME_UDS_VARIANT = "old"
BUILTIN_RUNTIME_CPU_INDEX = 0
# Preserve the already-shipped B4512000 live byte sequence exactly. The analyzed
# Sienna ignores the five DID-0203 data bytes, while the generalized RE route model
# uses 01 00 00 00 00 for CPU0. Keep that generalized convention plan-only until a
# target that needs it is explicitly enabled.
BUILTIN_RUNTIME_DID_0203 = b"\x00" * 5

# MEM-SAFE-001 is verified from this exact CodeFlash. Cross-vehicle bootstrap reuse does
# not silently transfer this memory-safety primitive. A future target must add equivalent
# target-specific evidence before live raw substitution can be enabled.
RAW_SUBSTITUTION_VERIFIED_CODEFLASH = frozenset({
  "21140bbd65e530a9e518a3e84e20e5d85679675bc09cc724cb177bb7c76bafde",
})

FF00_TRIGGER_ADDR = 0x000E0000
FF00_TRIGGER_SIZE = 0x8000


class EphemeralRuntimeError(ValueError):
  pass


def bootstrap_protocol_values(*, uds_variant: str, cpu_index: int) -> dict:
  """Construct Denso bootstrap dialect fields without granting live authority.

  ``old`` uses routine magic 45 00 and ``new`` uses 45 01. CPU0 uses memory-ID 1
  and DID 0203 = 01 00 00 00 00; CPU1 uses memory-ID 0 and five zero bytes.
  These are request-construction semantics only: selecting either value is not evidence
  that a target accepts that protocol path.
  """
  if uds_variant not in ("old", "new"):
    raise EphemeralRuntimeError("UDS variant must be old or new")
  if cpu_index not in (0, 1):
    raise EphemeralRuntimeError("cpu_index must be 0 or 1")
  return {
    "uds_variant": uds_variant,
    "cpu_index": cpu_index,
    "memory_id": 1 if cpu_index == 0 else 0,
    # Exact F33 and the older Toyota stack use zero DID 0203. The CPU0
    # 01 00 00 00 00 offset selector belongs to the new-stack grammar.
    "did_0203": b"\x01\x00\x00\x00\x00" if uds_variant == "new" and cpu_index == 0 else b"\x00" * 5,
    "routine_magic": b"\x45\x01" if uds_variant == "new" else b"\x45\x00",
  }


def _sha256(data: bytes) -> str:
  return hashlib.sha256(data).hexdigest()


def _hex_u32(value, name: str) -> int:
  try:
    parsed = int(value, 0) if isinstance(value, str) else int(value)
  except (TypeError, ValueError) as e:
    raise EphemeralRuntimeError(f"{name} is not an integer") from e
  if not 0 <= parsed <= 0xFFFFFFFF:
    raise EphemeralRuntimeError(f"{name} must fit uint32")
  return parsed


def _json_bytes(raw: bytes, name: str) -> dict:
  if len(raw) > MAX_IMPORT_JSON:
    raise EphemeralRuntimeError(f"{name} is unexpectedly large")
  try:
    value = json.loads(raw.decode("utf-8"))
  except (UnicodeDecodeError, json.JSONDecodeError) as e:
    raise EphemeralRuntimeError(f"{name} is not valid UTF-8 JSON") from e
  if not isinstance(value, dict):
    raise EphemeralRuntimeError(f"{name} must contain a JSON object")
  return value


def _atomic_write(path: Path, data: bytes) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
  try:
    with os.fdopen(fd, "wb") as fh:
      fh.write(data)
      fh.flush()
      os.fsync(fh.fileno())
    os.replace(temporary_name, path)
  except BaseException:
    try:
      os.unlink(temporary_name)
    except OSError:
      pass
    raise


def _validate_bootstrap_join(manifest: dict, f181: str) -> dict:
  bootstrap = manifest.get("authenticated_bootstrap_profile")
  if not isinstance(bootstrap, dict):
    raise EphemeralRuntimeError("target manifest has no authenticated bootstrap profile")
  if bootstrap.get("id") != PROFILE_ID:
    raise EphemeralRuntimeError("target manifest bootstrap profile is not the locally reviewed family")
  checks = (
    (bootstrap.get("security_access_secret"), BOOT_SA_SECRET.hex(), "boot SecurityAccess secret"),
    (bootstrap.get("security_access_data_record"), SECURITY_ACCESS_DATA_RECORD.hex(), "SecurityAccess data record"),
    (bootstrap.get("did_0201_default"), DID_0201_DEFAULT.hex(), "DID 0201 default"),
    (bootstrap.get("did_0202_default"), DID_0202_DEFAULT.hex(), "DID 0202 default"),
  )
  for actual, expected, label in checks:
    if str(actual).lower() != expected:
      raise EphemeralRuntimeError(f"target manifest {label} disagrees with local bootstrap evidence")
  if _hex_u32(bootstrap.get("authenticated_download_base"), "bootstrap download base") != DOWNLOAD_BASE:
    raise EphemeralRuntimeError("target manifest bootstrap download base disagrees with local evidence")
  if _hex_u32(bootstrap.get("authenticated_download_size"), "bootstrap download size") != DOWNLOAD_SIZE:
    raise EphemeralRuntimeError("target manifest bootstrap download size disagrees with local evidence")
  if _hex_u32(bootstrap.get("verify_routine"), "bootstrap verify routine") != VERIFY_ROUTINE:
    raise EphemeralRuntimeError("target manifest verify routine disagrees with local evidence")
  if _hex_u32(bootstrap.get("execute_routine"), "bootstrap execute routine") != EXECUTE_ROUTINE:
    raise EphemeralRuntimeError("target manifest execute routine disagrees with local evidence")
  matched = bootstrap.get("matched_evidence", [])
  if not isinstance(matched, list) or not any(row.get("software_id") == f181 for row in matched if isinstance(row, dict)):
    raise EphemeralRuntimeError("target manifest bootstrap evidence is not bound to this F181")
  return bootstrap


def inspect_command5_proxy_geometry(geometry: dict) -> dict:
  """Expose command-5 proxy geometry as static evidence only.

  The current B451 resolver records enough addresses to build the RE RAM proxy, but
  protected slot-4 command-5 permission is still a live hardware unknown. This helper
  intentionally returns no execution primitive and imports no XCP mailbox writer.
  """
  if geometry.get("command5_dispatch_address") in (None, ""):
    return {
      "available": False,
      "slot4_permission": "unknown",
      "execution_exposed": False,
      "mailbox_writer_imported": False,
    }
  required = (
    "command5_dispatch_address", "command5_done_flag", "command5_driver_record",
    "command5_key_selector", "command5_mailbox_address", "command5_mailbox_size",
    "command5_status_flag",
  )
  missing = [name for name in required if geometry.get(name) in (None, "")]
  if missing:
    raise EphemeralRuntimeError(f"target manifest has incomplete command-5 proxy geometry: {', '.join(missing)}")
  mailbox = _hex_u32(geometry["command5_mailbox_address"], "command-5 mailbox")
  mailbox_size = _hex_u32(geometry["command5_mailbox_size"], "command-5 mailbox size")
  return {
    "available": True,
    "dispatcher": f"0x{_hex_u32(geometry['command5_dispatch_address'], 'command-5 dispatcher'):08X}",
    "driver_record": int(geometry["command5_driver_record"]),
    "key_selector": int(geometry["command5_key_selector"]),
    "done_flag": f"0x{_hex_u32(geometry['command5_done_flag'], 'command-5 done flag'):08X}",
    "status_flag": f"0x{_hex_u32(geometry['command5_status_flag'], 'command-5 status flag'):08X}",
    "mailbox": f"0x{mailbox:08X}",
    "mailbox_size": mailbox_size,
    "mailbox_end_exclusive": f"0x{mailbox + mailbox_size:08X}",
    "mailbox_transport": str(geometry.get("command5_mailbox_transport", "")),
    "slot4_permission": "dynamic-unknown",
    "execution_exposed": False,
    "mailbox_writer_imported": False,
  }


def inspect_runtime_target_manifest(manifest_raw: bytes, *, expected_f181: str | None = None) -> dict:
  """Validate resolver evidence without treating it as an executable runtime package.

  This intentionally accepts resolver outputs such as the H/F Corolla manifests whose
  semantic analysis is complete but whose steering bridge is unsupported. No canary,
  bootstrap fixture, write authority, or live execution path is created by this function.
  """
  manifest = _json_bytes(manifest_raw, "target manifest")
  if manifest.get("schema") != RUNTIME_SCHEMA:
    raise EphemeralRuntimeError("unsupported ephemeral runtime target-manifest schema")
  image = manifest.get("image")
  if not isinstance(image, dict):
    raise EphemeralRuntimeError("target manifest is missing image identity")
  image_sha = str(image.get("sha256", "")).lower()
  if len(image_sha) != 64 or any(c not in "0123456789abcdef" for c in image_sha):
    raise EphemeralRuntimeError("target manifest has an invalid CodeFlash SHA-256")
  if int(image.get("size", 0)) != 0x100000:
    raise EphemeralRuntimeError("target manifest is not bound to an exact 1 MiB P1M-E CodeFlash image")
  software_ids = [str(value) for value in image.get("software_ids", [])]

  bootstrap = manifest.get("authenticated_bootstrap_profile")
  matched = bootstrap.get("matched_evidence", []) if isinstance(bootstrap, dict) else []
  matched_ids = [str(row.get("software_id")) for row in matched
                 if isinstance(row, dict) and row.get("software_id") in BOOTSTRAP_TARGETS]
  if expected_f181 is not None:
    target = normalize_f181(expected_f181)
  elif len(matched_ids) == 1:
    target = matched_ids[0]
  else:
    raise EphemeralRuntimeError("target manifest does not identify one exact bootstrap-evidence F181")
  if target not in software_ids:
    raise EphemeralRuntimeError(f"runtime target manifest CodeFlash does not contain target F181 {target}")
  _validate_bootstrap_join(manifest, target)

  geometry = manifest.get("ram_execution_geometry")
  secoc = manifest.get("secoc_records")
  if not isinstance(geometry, dict) or not isinstance(secoc, dict):
    raise EphemeralRuntimeError("target manifest is missing RAM/SecOC resolver evidence")
  required = [str(value) for value in secoc.get("steering_bridge_required_ids", [])]
  missing = [str(value) for value in secoc.get("steering_bridge_missing_ids", [])]
  incompatible = [str(value) for value in secoc.get("steering_bridge_incompatible_ids", [])]
  return {
    "f181": target,
    "manifest_sha256": _sha256(manifest_raw),
    "codeflash_sha256": image_sha,
    "status": str(manifest.get("status", "")),
    "runtime_build_ready": manifest.get("runtime_build_ready") is True,
    "ram_geometry_status": str(geometry.get("status", "")),
    "ram_geometry_selection_source": str(geometry.get("selection_source", "")),
    "secoc_record_count": int(secoc.get("record_count", len(secoc.get("records", [])))),
    "steering_bridge_applicable": secoc.get("steering_bridge_applicable") is True,
    "steering_bridge_required_ids": required,
    "steering_bridge_missing_ids": missing,
    "steering_bridge_incompatible_ids": incompatible,
    "command5_proxy_evidence": inspect_command5_proxy_geometry(geometry),
    "evidence_only": manifest.get("runtime_build_ready") is not True,
    "bridge_execution_exposed": False,
  }


def builtin_runtime_evidence(f181: str) -> dict | None:
  target = normalize_f181(f181)
  path = FOREIGN_EVIDENCE_MANIFEST_PATHS.get(target)
  if path is None or not path.is_file():
    return None
  return inspect_runtime_target_manifest(path.read_bytes(), expected_f181=target)


def validate_runtime_package(manifest_raw: bytes, audit_raw: bytes, canary: bytes,
                             *, expected_f181: str | None = None) -> dict:
  manifest = _json_bytes(manifest_raw, "target manifest")
  audit = _json_bytes(audit_raw, "canary audit")
  if manifest.get("schema") != RUNTIME_SCHEMA:
    raise EphemeralRuntimeError("unsupported ephemeral runtime target-manifest schema")
  if manifest.get("status") != "runtime-build-ready" or manifest.get("runtime_build_ready") is not True:
    raise EphemeralRuntimeError("target manifest is not runtime-build-ready")

  image = manifest.get("image")
  geometry = manifest.get("ram_execution_geometry")
  if not isinstance(image, dict) or not isinstance(geometry, dict):
    raise EphemeralRuntimeError("target manifest is missing image/RAM geometry")
  image_sha = str(image.get("sha256", "")).lower()
  if len(image_sha) != 64 or any(c not in "0123456789abcdef" for c in image_sha):
    raise EphemeralRuntimeError("target manifest has an invalid CodeFlash SHA-256")
  if int(image.get("size", 0)) != 0x100000:
    raise EphemeralRuntimeError("target manifest is not bound to an exact 1 MiB P1M-E CodeFlash image")
  software_ids = [str(value) for value in image.get("software_ids", [])]
  if expected_f181 is not None:
    target = normalize_f181(expected_f181)
    if target not in software_ids:
      raise EphemeralRuntimeError(f"runtime package CodeFlash does not contain target F181 {target}")
  else:
    targets = [value for value in software_ids if value in BOOTSTRAP_TARGETS]
    if len(targets) != 1:
      raise EphemeralRuntimeError("runtime package does not identify one known EPS F181")
    target = targets[0]

  if geometry.get("status") != "verified" or geometry.get("selection_source") != "image-sha-bound":
    raise EphemeralRuntimeError("runtime RAM retention geometry is not exact-image verified")
  if str(geometry.get("codeflash_sha256", "")).lower() != image_sha:
    raise EphemeralRuntimeError("runtime RAM geometry CodeFlash identity mismatch")
  retained_base = _hex_u32(geometry.get("retained_application_rwx_base"), "retained R/W/X base")
  retained_end = _hex_u32(geometry.get("retained_application_rwx_end_exclusive"), "retained R/W/X end")
  retained_size = _hex_u32(geometry.get("retained_application_rwx_size"), "retained R/W/X size")
  callback_base = _hex_u32(geometry.get("payload_callback_base"), "payload callback base")
  callback_cell = _hex_u32(geometry.get("payload_callback_cell"), "payload callback cell")
  heartbeat = _hex_u32(geometry.get("canary_observation_address"), "canary observation address")
  if retained_end - retained_base != retained_size or callback_base != retained_base:
    raise EphemeralRuntimeError("runtime retained/callback geometry is internally inconsistent")
  if not retained_base <= callback_base < retained_end:
    raise EphemeralRuntimeError("runtime callback base is outside retained R/W/X geometry")
  if not (DOWNLOAD_BASE <= callback_cell <= DOWNLOAD_BASE + DOWNLOAD_SIZE - 4):
    raise EphemeralRuntimeError("payload callback cell is outside authenticated download window")

  _validate_bootstrap_join(manifest, target)

  if audit.get("schema") != CANARY_AUDIT_SCHEMA or audit.get("review_status") != CANARY_REVIEW_STATUS:
    raise EphemeralRuntimeError("runtime package does not contain the reviewed inert-canary audit")
  contract = audit.get("compile_contract")
  shellcode = audit.get("shellcode")
  if not isinstance(contract, dict) or not isinstance(shellcode, dict):
    raise EphemeralRuntimeError("canary audit is missing compile/shellcode contracts")
  if str(contract.get("target_codeflash_sha256", "")).lower() != image_sha:
    raise EphemeralRuntimeError("canary audit target CodeFlash does not match target manifest")
  if str(contract.get("target_manifest_sha256", "")).lower() != _sha256(manifest_raw):
    raise EphemeralRuntimeError("canary audit does not bind the exact imported target manifest bytes")
  if int(contract.get("entry_offset", -1)) != 0 or int(contract.get("relocations", -1)) != 0:
    raise EphemeralRuntimeError("canary must be entry-zero and relocation-free")
  if _hex_u32(contract.get("retained_base"), "canary retained base") != retained_base:
    raise EphemeralRuntimeError("canary audit retained base disagrees with target manifest")
  if _hex_u32(contract.get("retained_end_exclusive"), "canary retained end") != retained_end:
    raise EphemeralRuntimeError("canary audit retained end disagrees with target manifest")
  if _hex_u32(contract.get("heartbeat_address"), "canary heartbeat") != heartbeat:
    raise EphemeralRuntimeError("canary heartbeat disagrees with target manifest")
  if len(canary) > MAX_CANARY_SIZE or len(canary) != int(shellcode.get("size", -1)):
    raise EphemeralRuntimeError("canary size does not match audited shellcode")
  if len(canary) > retained_size:
    raise EphemeralRuntimeError("canary does not fit retained R/W/X region")
  canary_sha = _sha256(canary)
  if canary_sha != str(shellcode.get("sha256", "")).lower():
    raise EphemeralRuntimeError("canary binary SHA-256 does not match audit")
  if int(shellcode.get("entry_offset", -1)) != 0:
    raise EphemeralRuntimeError("audited canary entry offset is not zero")

  return {
    "schema": PACKAGE_SCHEMA,
    "f181": target,
    "codeflash_sha256": image_sha,
    "target_manifest_sha256": _sha256(manifest_raw),
    "canary_sha256": canary_sha,
    "canary_size": len(canary),
    "retained_base": f"0x{retained_base:08X}",
    "retained_end_exclusive": f"0x{retained_end:08X}",
    "callback_cell": f"0x{callback_cell:08X}",
    "heartbeat_address": f"0x{heartbeat:08X}",
    "heartbeat_observation_method": str(geometry.get("canary_observation_method", "")),
    "bootstrap": public_bootstrap_status(target),
    "command5_proxy_evidence": inspect_command5_proxy_geometry(geometry),
    "raw_substitution_verified": image_sha in RAW_SUBSTITUTION_VERIFIED_CODEFLASH,
    "canary_static_ready": True,
    "bridge_artifact_present": False,
    "bridge_execution_exposed": False,
  }


def _package_paths(source: str) -> tuple[Path, Path, Path]:
  if source == "imported":
    return IMPORTED_MANIFEST_PATH, IMPORTED_AUDIT_PATH, IMPORTED_CANARY_PATH
  if source == "builtin":
    return BUILTIN_MANIFEST_PATH, BUILTIN_AUDIT_PATH, BUILTIN_CANARY_PATH
  raise EphemeralRuntimeError(f"unknown runtime package source: {source}")


def load_runtime_package(f181: str) -> tuple[dict, bytes, bytes, bytes, str] | None:
  target = normalize_f181(f181)
  for source in ("imported", "builtin"):
    manifest_path, audit_path, canary_path = _package_paths(source)
    if not all(path.is_file() for path in (manifest_path, audit_path, canary_path)):
      continue
    manifest_raw, audit_raw, canary = manifest_path.read_bytes(), audit_path.read_bytes(), canary_path.read_bytes()
    try:
      metadata = validate_runtime_package(manifest_raw, audit_raw, canary, expected_f181=target)
    except EphemeralRuntimeError:
      continue
    metadata["source"] = source
    return metadata, manifest_raw, audit_raw, canary, source
  return None


def persist_runtime_package(manifest_raw: bytes, audit_raw: bytes, canary: bytes, *,
                            expected_f181: str, bootstrap_fixture: bytes | None = None,
                            bootstrap_fixture_sha256: str = "", bootstrap_fixture_evidence: str = "") -> dict:
  metadata = validate_runtime_package(manifest_raw, audit_raw, canary, expected_f181=expected_f181)
  target = metadata["f181"]
  imported_fixture = None
  if bootstrap_fixture is not None:
    if len(bootstrap_fixture) != MAX_BOOTSTRAP_SIZE:
      raise EphemeralRuntimeError("imported bootstrap fixture must be exactly 0x1000 bytes")
    actual_sha = _sha256(bootstrap_fixture)
    if actual_sha != bootstrap_fixture_sha256.lower():
      raise EphemeralRuntimeError("imported bootstrap fixture SHA-256 mismatch")
    if not bootstrap_fixture_evidence.strip():
      raise EphemeralRuntimeError("imported bootstrap fixture requires a target-acceptance evidence note")
    imported_fixture = {
      "sha256": actual_sha,
      "size": len(bootstrap_fixture),
      "evidence": bootstrap_fixture_evidence.strip(),
      "evidence_grade": "operator-supplied-target-acceptance",
    }
  _atomic_write(IMPORTED_MANIFEST_PATH, manifest_raw)
  _atomic_write(IMPORTED_AUDIT_PATH, audit_raw)
  _atomic_write(IMPORTED_CANARY_PATH, canary)
  if imported_fixture is not None:
    _atomic_write(IMPORTED_BOOTSTRAP_PATH, bootstrap_fixture)
  else:
    try:
      IMPORTED_BOOTSTRAP_PATH.unlink()
    except FileNotFoundError:
      pass
  package_metadata = {
    **metadata,
    "source": "imported",
    "bootstrap_fixture": imported_fixture,
    "imported_utc": datetime.now(UTC).timestamp(),
  }
  _atomic_write(IMPORTED_METADATA_PATH, (json.dumps(package_metadata, indent=2, sort_keys=True) + "\n").encode())
  try:
    CANARY_VALIDATION_PATH.unlink()
  except FileNotFoundError:
    pass
  return public_runtime_status(target)


def import_runtime_package_json(request: dict, *, expected_f181: str) -> dict:
  def decode(name: str, required: bool = True) -> bytes | None:
    value = request.get(name)
    if value in (None, "") and not required:
      return None
    if not isinstance(value, str) or not value:
      raise EphemeralRuntimeError(f"{name} is required")
    try:
      return base64.b64decode(value, validate=True)
    except Exception as e:
      raise EphemeralRuntimeError(f"{name} is not valid base64") from e
  return persist_runtime_package(
    decode("target_manifest_b64"),
    decode("canary_audit_b64"),
    decode("canary_b64"),
    expected_f181=expected_f181,
    bootstrap_fixture=decode("bootstrap_fixture_b64", required=False),
    bootstrap_fixture_sha256=str(request.get("bootstrap_fixture_sha256", "")),
    bootstrap_fixture_evidence=str(request.get("bootstrap_fixture_evidence", "")),
  )


def _validation_record(f181: str, codeflash_sha: str, canary_sha: str) -> dict | None:
  try:
    record = json.loads(CANARY_VALIDATION_PATH.read_text(encoding="utf-8"))
  except (OSError, json.JSONDecodeError):
    return None
  if not isinstance(record, dict):
    return None
  if (record.get("f181"), record.get("codeflash_sha256"), record.get("canary_sha256")) != (f181, codeflash_sha, canary_sha):
    return None
  return record


def _selected_bootstrap_fixture(f181: str, package_source: str) -> tuple[bytes, dict]:
  builtin = Path(PAYLOAD_PATH).read_bytes()
  builtin_sha = _sha256(builtin)
  if fixture_is_evidenced(f181, builtin_sha):
    return builtin, {
      "source": "built-in-public-ram-payload",
      "sha256": builtin_sha,
      "size": len(builtin),
      "target_evidenced": True,
    }
  if package_source == "imported" and IMPORTED_BOOTSTRAP_PATH.is_file() and IMPORTED_METADATA_PATH.is_file():
    try:
      metadata = json.loads(IMPORTED_METADATA_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
      raise EphemeralRuntimeError("imported runtime package metadata is corrupt") from e
    fixture_meta = metadata.get("bootstrap_fixture")
    fixture = IMPORTED_BOOTSTRAP_PATH.read_bytes()
    if not isinstance(fixture_meta, dict) or len(fixture) != MAX_BOOTSTRAP_SIZE or _sha256(fixture) != fixture_meta.get("sha256"):
      raise EphemeralRuntimeError("imported bootstrap fixture no longer matches package metadata")
    return fixture, {"source": "imported-target-accepted-fixture", **fixture_meta, "target_evidenced": False}
  raise EphemeralRuntimeError(
    "runtime package is valid, but this F181 has no exact built-in bootstrap fixture; import a target-accepted 4 KiB fixture"
  )


def public_runtime_status(f181: str) -> dict:
  target = normalize_f181(f181)
  loaded = load_runtime_package(target) if target else None
  evidence = builtin_runtime_evidence(target) if target else None
  if loaded is None:
    message = "No SHA-bound ephemeral runtime canary package is installed for this F181."
    if evidence is not None:
      message = (
        "Resolver evidence is bundled for this exact F181, but it is evidence-only and cannot be executed. " +
        f"Status: {evidence['status']}; steering bridge applicable: {evidence['steering_bridge_applicable']}."
      )
    return {
      "present": False,
      "f181": target,
      "canary_static_ready": False,
      "scheduler_observed": False,
      "reset_to_stock_verified": False,
      "bridge_execution_exposed": False,
      "target_evidence": evidence or {},
      "message": message,
    }
  metadata, _, _, _, source = loaded
  try:
    _, fixture_meta = _selected_bootstrap_fixture(target, source)
    fixture_ready = True
    fixture_error = ""
  except (OSError, EphemeralRuntimeError) as e:
    fixture_meta = None
    fixture_ready = False
    fixture_error = str(e)
  validation = _validation_record(target, metadata["codeflash_sha256"], metadata["canary_sha256"])
  return {
    "present": True,
    **metadata,
    "source": source,
    "bootstrap_fixture_ready": fixture_ready,
    "bootstrap_fixture": fixture_meta,
    "raw_substitution_verified": bool(metadata["raw_substitution_verified"]),
    "live_canary_ready": bool(fixture_ready and metadata["raw_substitution_verified"]),
    "scheduler_observed": bool(validation and validation.get("scheduler_observed")),
    "reset_to_stock_verified": bool(validation and validation.get("reset_to_stock_verified")),
    "validation": validation or {},
    "bridge_execution_exposed": False,
    "message": (
      "Audited inert canary package is ready for isolated-bench execution."
      if fixture_ready and metadata["raw_substitution_verified"] else
      fixture_error or "Static runtime package is valid, but the target execution primitive is not verified for live substitution."
    ),
  }


def _download_record(address: int, length: int, *, memory_id: int) -> bytes:
  if not 0 <= memory_id <= 0xFF:
    raise EphemeralRuntimeError("RequestDownload memory ID must fit one byte")
  if length <= 0 or length > 0xFFFFFFFF or not 0 <= address <= 0xFFFFFFFF:
    raise EphemeralRuntimeError("RequestDownload address/length must be non-wrapping uint32 values")
  if address + length > 0x100000000:
    raise EphemeralRuntimeError("RequestDownload range wraps uint32")
  return b"\x01\x46" + bytes((memory_id, 0)) + struct.pack("!II", address, length)


def _request_download_record(address: int, length: int, *, memory_id: int = 1) -> bytes:
  if not 1 <= length <= MAX_RAW_CHUNK:
    raise EphemeralRuntimeError("raw substitution chunks must be 1..15 bytes")
  if not DOWNLOAD_BASE <= address or address + length > DOWNLOAD_BASE + DOWNLOAD_SIZE:
    raise EphemeralRuntimeError("raw substitution is outside authenticated download window")
  return _download_record(address, length, memory_id=memory_id)


def bootstrap_protocol_plan(*, uds_variant: str, cpu_index: int) -> dict:
  protocol = bootstrap_protocol_values(uds_variant=uds_variant, cpu_index=cpu_index)
  magic = protocol["routine_magic"]
  return {
    **protocol,
    "request_download": _download_record(DOWNLOAD_BASE, DOWNLOAD_SIZE, memory_id=protocol["memory_id"]),
    "verify_data": magic + struct.pack("!II", DOWNLOAD_BASE, DOWNLOAD_SIZE),
    "execution_trigger": b"\x31\x01\xff\x00" + magic + struct.pack("!II", FF00_TRIGGER_ADDR, FF00_TRIGGER_SIZE),
  }


def builtin_runtime_protocol_plan() -> dict:
  """Return the exact already-reviewed B4512000 live request shape.

  The generalized cpu-index model is useful for planning F3/F4 and newer-stack work,
  but it must not silently rewrite bytes on the only built-in live target.
  """
  plan = bootstrap_protocol_plan(
    uds_variant=BUILTIN_RUNTIME_UDS_VARIANT,
    cpu_index=BUILTIN_RUNTIME_CPU_INDEX,
  )
  return {**plan, "did_0203": BUILTIN_RUNTIME_DID_0203}


def _raw_substitution_plan(base: int, canary: bytes, callback_cell: int) -> list[tuple[int, bytes]]:
  chunks = [(base + offset, canary[offset:offset + MAX_RAW_CHUNK])
            for offset in range(0, len(canary), MAX_RAW_CHUNK)]
  chunks.append((callback_cell, struct.pack("<I", base)))
  return chunks


BOOT_SA_REQUIRED_DELAY_SECONDS = 10.25


def _request_boot_seed_with_required_delay(boot, request_seed_access_type, *, sleep_fn=time.sleep):
  """Request the boot SA seed, respecting the verified NRC 0x37 delay exactly when present.

  SEC-BOOT-010 proves the delay is a volatile ~10 s TAUJ1 timer after the second bad
  SEND_KEY, not persistent/NVRAM lockout. Normal programming handoff clears it, so never
  impose this delay pre-emptively. If an already-armed target returns NRC 0x37, wait once
  and retry the same read-only REQUEST_SEED. Any other failure propagates unchanged.
  """
  try:
    return boot.security_access(request_seed_access_type, data_record=SECURITY_ACCESS_DATA_RECORD)
  except Exception as e:
    if getattr(e, "error_code", None) != 0x37:
      raise
  sleep_fn(BOOT_SA_REQUIRED_DELAY_SECONDS)
  return boot.security_access(request_seed_access_type, data_record=SECURITY_ACCESS_DATA_RECORD)


def run_inert_canary(*, expected_f181: str, bench_isolated: bool,
                     progress_cb=None, validate_reset: bool = True) -> dict:
  """Execute only the audited inert canary, then prove heartbeat and reset-to-stock.

  Live execution is intentionally limited to targets whose CodeFlash has an explicit
  target-specific post-auth raw-substitution proof. No steering bridge is present here.
  """
  if not bench_isolated:
    raise EphemeralRuntimeError("inert canary execution requires explicit isolated-bench acknowledgement")
  if not is_agnos():
    raise NotAGNOSError
  target = normalize_f181(expected_f181)
  loaded = load_runtime_package(target)
  if loaded is None:
    raise EphemeralRuntimeError("no validated runtime package is installed for the identified F181")
  metadata, manifest_raw, _, canary, source = loaded
  if not metadata["raw_substitution_verified"]:
    raise EphemeralRuntimeError(
      "runtime retention is resolved, but post-auth raw substitution is not target-verified for this CodeFlash"
    )
  manifest = json.loads(manifest_raw)
  geometry = manifest["ram_execution_geometry"]
  runtime_base = _hex_u32(geometry["payload_callback_base"], "runtime base")
  callback_cell = _hex_u32(geometry["payload_callback_cell"], "callback cell")
  heartbeat = _hex_u32(geometry["canary_observation_address"], "heartbeat")
  bootstrap_fixture, bootstrap_meta = _selected_bootstrap_fixture(target, source)
  cb = progress_cb or (lambda **_: None)

  from Crypto.Cipher import AES
  from opendbc.car.isotp import isotp_send
  from opendbc.car.uds import ACCESS_TYPE, RESET_TYPE, ROUTINE_CONTROL_TYPE, SERVICE_TYPE, SESSION_TYPE

  panda = TSKExtractor._connect_panda()
  route = discover_eps_route_with_routing(panda, TSKExtractor.CANDIDATE_BUSES,
                                          preferred_tx=TSKExtractor.ADDR,
                                          addresses=[TSKExtractor.ADDR])
  if route is None or route["tx_bus"] != route["rx_bus"]:
    raise EphemeralRuntimeError("no same-bus EPS diagnostic route answered")
  client = uds_client(panda, route, timeout=0.3, response_pending_timeout=3.0)
  actual_f181 = normalize_f181(bytes(client.read_data_by_identifier(0xF181)))
  if actual_f181 != target:
    raise EphemeralRuntimeError(f"identified EPS changed from {target} to {actual_f181}")
  cb(step="identified", message=f"F181 {target}; runtime package and route bound")

  try:
    boot_route, handoff = enter_programming_bootloader(panda, route, prepare_sessions=True, settle_extended=0.7)
  except ProgrammingHandoffError as e:
    raise EphemeralRuntimeError(f"programming handoff failed: {e}") from e
  cb(step="programming", message="bootloader reappeared on preserved route")
  boot = uds_client(panda, boot_route, timeout=0.3, response_pending_timeout=3.0)
  boot.diagnostic_session_control(SESSION_TYPE.DEFAULT)
  boot.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
  boot.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)

  seed = _request_boot_seed_with_required_delay(boot, ACCESS_TYPE.REQUEST_SEED)
  key = AES.new(BOOT_SA_SECRET, AES.MODE_ECB).decrypt(SECURITY_ACCESS_DATA_RECORD)
  key = AES.new(key, AES.MODE_ECB).encrypt(seed)
  boot.security_access(ACCESS_TYPE.SEND_KEY, key)
  cb(step="security-access", message="boot SecurityAccess accepted")

  protocol = builtin_runtime_protocol_plan()
  boot.write_data_by_identifier(0x203, protocol["did_0203"])
  boot.write_data_by_identifier(0x201, DID_0201_DEFAULT)
  boot.write_data_by_identifier(0x202, DID_0202_DEFAULT)
  boot._uds_request(SERVICE_TYPE.REQUEST_DOWNLOAD, data=protocol["request_download"])
  for index, offset in enumerate(range(0, len(bootstrap_fixture), 0x400), start=1):
    boot.transfer_data(index, bootstrap_fixture[offset:offset + 0x400])
  boot.request_transfer_exit()
  boot.routine_control(ROUTINE_CONTROL_TYPE.START, VERIFY_ROUTINE, protocol["verify_data"])
  cb(step="bootstrap-authenticated", message="target-accepted 4 KiB bootstrap passed 0x10F0")

  substitutions = _raw_substitution_plan(runtime_base, canary, callback_cell)
  for index, (address, data) in enumerate(substitutions):
    boot._uds_request(
      SERVICE_TYPE.REQUEST_DOWNLOAD,
      data=_request_download_record(address, len(data), memory_id=protocol["memory_id"]),
    )
    boot.transfer_data(1, data)
    boot.request_transfer_exit()
    if index == len(substitutions) - 1:
      cb(step="callback-last", message=f"callback cell 0x{callback_cell:08X} written last")
  isotp_send(panda, protocol["execution_trigger"], boot_route["tx"], bus=boot_route["tx_bus"])
  cb(step="triggered", message="inert runtime triggered; waiting for application diagnostics")

  deadline = time.monotonic() + 8.0
  app_route = None
  while time.monotonic() < deadline:
    app_route = rediscover_route(panda, boot_route, buses=[boot_route["tx_bus"]], preferred_timeout=0.35, scan_timeout=0.1)
    if app_route is not None:
      break
    time.sleep(0.1)
  if app_route is None:
    raise EphemeralRuntimeError("application diagnostics did not reappear after canary trigger")
  app = uds_client(panda, app_route, timeout=0.5, response_pending_timeout=1.0)
  app.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
  first = int.from_bytes(read_memory_with_id(app, SERVICE_TYPE, RAM_ID, heartbeat, 4), "little")
  time.sleep(0.15)
  second = int.from_bytes(read_memory_with_id(app, SERVICE_TYPE, RAM_ID, heartbeat, 4), "little")
  scheduler_observed = second != first
  if not scheduler_observed:
    raise EphemeralRuntimeError(f"canary heartbeat did not advance ({first:#x} -> {second:#x})")
  cb(step="heartbeat", message=f"heartbeat advanced {first:#x} -> {second:#x}")

  reset_verified = False
  post_reset_value = None
  reset_route = None
  if validate_reset:
    try:
      app.ecu_reset(RESET_TYPE.HARD)
    except Exception:
      # A disappearing endpoint can overtake the final response; reappearance below is authoritative.
      pass
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
      reset_route = rediscover_route(panda, app_route, buses=[app_route["tx_bus"]], preferred_timeout=0.35, scan_timeout=0.1)
      if reset_route is not None:
        break
      time.sleep(0.1)
    if reset_route is None:
      raise EphemeralRuntimeError("EPS did not reappear after hardware reset; reset-to-stock proof failed")
    reset_app = uds_client(panda, reset_route, timeout=0.5, response_pending_timeout=1.0)
    reset_f181 = normalize_f181(bytes(reset_app.read_data_by_identifier(0xF181)))
    if reset_f181 != target:
      raise EphemeralRuntimeError("post-reset EPS identity changed")
    reset_app.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    post_reset_value = int.from_bytes(read_memory_with_id(reset_app, SERVICE_TYPE, RAM_ID, heartbeat, 4), "little")
    time.sleep(0.15)
    post_reset_value_2 = int.from_bytes(read_memory_with_id(reset_app, SERVICE_TYPE, RAM_ID, heartbeat, 4), "little")
    reset_verified = post_reset_value == post_reset_value_2
    if not reset_verified:
      raise EphemeralRuntimeError("heartbeat continued after reset; runtime did not return to stock behavior")
    cb(step="reset-to-stock", message=f"heartbeat stopped after reset at {post_reset_value:#x}")

  record = {
    "schema": VALIDATION_SCHEMA,
    "status": "passed" if scheduler_observed and (reset_verified or not validate_reset) else "incomplete",
    "f181": target,
    "codeflash_sha256": metadata["codeflash_sha256"],
    "canary_sha256": metadata["canary_sha256"],
    "scheduler_observed": scheduler_observed,
    "heartbeat_address": f"0x{heartbeat:08X}",
    "heartbeat_first": first,
    "heartbeat_second": second,
    "reset_to_stock_verified": reset_verified,
    "post_reset_heartbeat": post_reset_value,
    "route": route_fields(route),
    "programming_handoff": handoff,
    "bootstrap_fixture": bootstrap_meta,
    "validated_utc": datetime.now(UTC).timestamp(),
    "bridge_execution_exposed": False,
  }
  _atomic_write(CANARY_VALIDATION_PATH, (json.dumps(record, indent=2, sort_keys=True) + "\n").encode())
  return record
