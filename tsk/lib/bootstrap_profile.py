#!/usr/bin/env python3
"""Evidence-graded authenticated-RAM bootstrap compatibility for Toyota/Denso EPS.

This is intentionally separate from application-time retained-RAM/runtime geometry.
A target can share the boot SecurityAccess/DID/download/0x10F0/0xFF00 contract without
proving that any RAM survives application startup, and sharing that bootstrap does not
prove that every encrypted 4 KiB fixture is accepted byte-for-byte on every calibration.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from tsk.lib.ram_exec_geometry import normalize_f181


PROFILE_ID = "denso-p1me-f05f-zero-did-febf-v1"
BOOT_SA_SECRET = bytes.fromhex("f05f36b7d78c03e24ab4faef2a57d044")
SECURITY_ACCESS_DATA_RECORD = bytes(16)
DID_0201_DEFAULT = bytes(16)
DID_0202_DEFAULT = bytes(16)
DOWNLOAD_BASE = 0xFEBF0000
DOWNLOAD_SIZE = 0x1000
VERIFY_ROUTINE = 0x10F0
EXECUTE_ROUTINE = 0xFF00

RAM_DUMP_FIXTURE_SHA256 = "d972d4bf432685217591768600a9abd7820d35b04a72270edc87074365356be2"
DATAFLASH_FIXTURE_SHA256 = "d48988366b5e6d2ddd7438caca5e6f6f02daba9b650263c323a2ffd770a06e34"
AUTORESET_DATAFLASH_FIXTURE_SHA256 = "bf62449f85648ea24708961749bf53f75f36083c01bcf54114d567da0e178725"


@dataclass(frozen=True)
class BootstrapTargetEvidence:
  software_id: str
  grade: str
  source: str
  fixture_transfer: str
  exact_fixture_sha256: frozenset[str] = frozenset()
  notes: str = ""

  def public_dict(self) -> dict:
    data = asdict(self)
    data["exact_fixture_sha256"] = sorted(self.exact_fixture_sha256)
    return data


# Source of truth for this transfer table:
# ghidra_rh850_analysis/data/variant_bootstrap_profiles.json.  The rows deliberately
# preserve bootstrap-family evidence separately from exact encrypted-fixture evidence.
BOOTSTRAP_TARGETS = {
  "8965B4512000": BootstrapTargetEvidence(
    software_id="8965B4512000",
    grade="verified",
    source="firmware-static + generated-artifact (SECOC-062/063)",
    fixture_transfer="exact-local-fixtures-verified",
    exact_fixture_sha256=frozenset({
      RAM_DUMP_FIXTURE_SHA256,
      DATAFLASH_FIXTURE_SHA256,
      AUTORESET_DATAFLASH_FIXTURE_SHA256,
    }),
    notes="Exact payload-gate proof; auto-reset derivative is rebuilt under the same verified gate.",
  ),
  "8965H1202000": BootstrapTargetEvidence(
    software_id="8965H1202000",
    grade="observed",
    source="community/albinoelephant/raw-20260818/MANIFEST.txt + recovered CodeFlash",
    fixture_transfer="target-built-range-payloads-observed",
    notes=("Contributor field acquisition executed target-built range-dump payloads through the shared "
           "authenticated-RAM path; exact acceptance of the repository Sienna fixture is not claimed."),
  ),
  "8965F1208000": BootstrapTargetEvidence(
    software_id="8965F1208000",
    grade="observed",
    source="community/spanconstant/raw-20260821/MANIFEST.txt + recovered CodeFlash",
    fixture_transfer="target-built-range-payloads-observed",
    notes=("Span's acquisition executed target-built range-dump payloads through the shared authenticated-RAM "
           "path; exact acceptance of the repository Sienna fixture is not claimed."),
  ),
  "8965B4209000": BootstrapTargetEvidence(
    software_id="8965B4209000",
    grade="external-source",
    source="SECOC-024 / pinned I-CAN-hack+Bk2ol lineage",
    fixture_transfer="shared-public-payload-reported",
    notes="Historical field-supported bootstrap family; exact repository-fixture acceptance is not pinned.",
  ),
  "8965B4233100": BootstrapTargetEvidence(
    software_id="8965B4233100",
    grade="external-source",
    source="SECOC-024 / pinned I-CAN-hack+Bk2ol lineage",
    fixture_transfer="shared-public-payload-reported",
    notes="Historical field-supported bootstrap family; exact repository-fixture acceptance is not pinned.",
  ),
  "8965B4509100": BootstrapTargetEvidence(
    software_id="8965B4509100",
    grade="external-source",
    source="SECOC-024 / pinned I-CAN-hack+Bk2ol lineage",
    fixture_transfer="shared-public-payload-reported",
    notes="Historical field-supported bootstrap family; exact repository-fixture acceptance is not pinned.",
  ),
  "8965B4514000": BootstrapTargetEvidence(
    software_id="8965B4514000",
    grade="external-source",
    source="SECOC-024 / pinned I-CAN-hack+Bk2ol lineage",
    fixture_transfer="shared-public-payload-reported",
    notes=("Partner execution is externally reported, but retained public artifacts do not identify which exact "
           "4 KiB ciphertext executed; require an explicitly target-accepted fixture."),
  ),
  "8965F3401200": BootstrapTargetEvidence(
    software_id="8965F3401200",
    grade="external-source",
    source="blurbdust SecOC flash patcher target table (SECOC-028/063)",
    fixture_transfer="shared-flash-payload-path-reported",
    notes="Dual-CPU target; shared bootstrap structure is reported, exact local TSK fixture is not pinned.",
  ),
  "8965F4207000": BootstrapTargetEvidence(
    software_id="8965F4207000",
    grade="external-source",
    source="blurbdust SecOC flash patcher target table (SECOC-028/063)",
    fixture_transfer="shared-flash-payload-path-reported",
    notes="Shared bootstrap structure is reported; exact local TSK fixture is not pinned.",
  ),
  "8965F4201000": BootstrapTargetEvidence(
    software_id="8965F4201000",
    grade="external-source",
    source="blurbdust SecOC flash patcher target table (SECOC-028/063)",
    fixture_transfer="shared-flash-payload-path-reported",
    notes="Shared bootstrap structure is reported; exact local TSK fixture is not pinned.",
  ),
}


class BootstrapProfileError(ValueError):
  pass


def known_bootstrap_target(f181: bytes | bytearray | str) -> BootstrapTargetEvidence | None:
  return BOOTSTRAP_TARGETS.get(normalize_f181(f181))


def fixture_is_evidenced(f181: bytes | bytearray | str, sha256: str) -> bool:
  target = known_bootstrap_target(f181)
  return bool(target and sha256.lower() in target.exact_fixture_sha256)


def require_bootstrap_target(f181: bytes | bytearray | str) -> BootstrapTargetEvidence:
  normalized = normalize_f181(f181)
  target = BOOTSTRAP_TARGETS.get(normalized)
  if target is None:
    raise BootstrapProfileError(
      f"no authenticated-RAM bootstrap profile is evidenced for EPS F181 {normalized or '<empty>'}"
    )
  return target


def require_evidenced_fixture(f181: bytes | bytearray | str, sha256: str) -> BootstrapTargetEvidence:
  target = require_bootstrap_target(f181)
  if sha256.lower() not in target.exact_fixture_sha256:
    raise BootstrapProfileError(
      f"bootstrap family {PROFILE_ID} covers {target.software_id}, but fixture {sha256.lower()} is not "
      "evidenced byte-for-byte for that F181"
    )
  return target


def public_bootstrap_status(f181: bytes | bytearray | str, *, fixture_sha256: str | None = None) -> dict:
  normalized = normalize_f181(f181)
  target = BOOTSTRAP_TARGETS.get(normalized)
  if target is None:
    return {
      "compatible": False,
      "profile_id": PROFILE_ID,
      "f181": normalized,
      "target_evidence": None,
      "fixture_sha256": fixture_sha256 or "",
      "fixture_evidenced": False,
      "message": "No exact-F181 bootstrap-family evidence is recorded for this target.",
    }
  fixture_ok = bool(fixture_sha256 and fixture_sha256.lower() in target.exact_fixture_sha256)
  return {
    "compatible": True,
    "profile_id": PROFILE_ID,
    "f181": normalized,
    "target_evidence": target.public_dict(),
    "security_access_level": "0x01/0x02",
    "download_base": f"0x{DOWNLOAD_BASE:08X}",
    "download_size": f"0x{DOWNLOAD_SIZE:X}",
    "verify_routine": f"0x{VERIFY_ROUTINE:04X}",
    "execute_routine": f"0x{EXECUTE_ROUTINE:04X}",
    "fixture_sha256": fixture_sha256 or "",
    "fixture_evidenced": fixture_ok,
    "message": (
      "Bootstrap family is evidenced and the selected fixture is target-evidenced."
      if fixture_ok else
      "Bootstrap family is evidenced, but exact encrypted-fixture acceptance remains a separate gate."
    ),
  }
