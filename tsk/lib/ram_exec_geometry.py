#!/usr/bin/env python3
"""Evidence-bound authenticated RAM-execution geometry for Toyota EPS tooling.

A programming-session handoff, a writable RAM address, or a shellcode linker VMA is not
sufficient evidence that an EPS accepts an authenticated RequestDownload at that address.
The bootloader payload path couples four things that must agree:

* the RequestDownload destination;
* the transferred payload length;
* the 0x10F0 verification address/length; and
* the callback address embedded in the authenticated payload package.

Only calibrations with evidence for that complete *bootloader* contract resolve automatically
here. This module does not claim that downloaded RAM survives application startup or is
application-executable; that separate contract is represented by the ephemeral-runtime target
manifest. Unknown calibrations fail closed. A future non-default boot geometry can be represented
only as an explicitly evidenced ``RamExecGeometry``; the separate linker-VMA observation type is
intentionally not accepted by the resolver.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
import struct


class RamExecGeometryError(ValueError):
  pass


@dataclass(frozen=True)
class RamExecGeometry:
  name: str
  load_addr: int
  size: int
  callback_addr: int
  target_f181: frozenset[str]
  evidence: str
  authenticated_download_verified: bool = True
  callback_verified: bool = True
  programming_handoff_verified: bool = True

  def validate(self) -> None:
    if not (0 <= self.load_addr <= 0xFFFFFFFF):
      raise RamExecGeometryError("RAM-exec load address must fit uint32")
    if self.size <= 0 or self.size > 0xFFFFFFFF:
      raise RamExecGeometryError("RAM-exec size must be a positive uint32")
    if not (0 <= self.callback_addr <= 0xFFFFFFFF):
      raise RamExecGeometryError("RAM-exec callback address must fit uint32")
    if not self.target_f181:
      raise RamExecGeometryError("RAM-exec geometry must name at least one exact target F181")
    if not self.evidence.strip():
      raise RamExecGeometryError("RAM-exec geometry requires an evidence/provenance label")
    if not self.authenticated_download_verified:
      raise RamExecGeometryError("authenticated RequestDownload geometry is not verified")
    if not self.callback_verified:
      raise RamExecGeometryError("authenticated payload callback geometry is not verified")

  def public_dict(self) -> dict:
    data = asdict(self)
    data["target_f181"] = sorted(self.target_f181)
    data["load_addr"] = f"0x{self.load_addr:08X}"
    data["size"] = f"0x{self.size:X}"
    data["callback_addr"] = f"0x{self.callback_addr:08X}"
    return data


@dataclass(frozen=True)
class LinkerVmaObservation:
  """External deployment evidence that is deliberately *not* executable geometry."""
  name: str
  link_vma: int
  evidence: str
  authenticated_download_addr: int | None = None
  authenticated_download_size: int | None = None
  callback_addr: int | None = None

  def public_dict(self) -> dict:
    return {
      "name": self.name,
      "link_vma": f"0x{self.link_vma:08X}",
      "evidence": self.evidence,
      "authenticated_download_addr": self.authenticated_download_addr,
      "authenticated_download_size": self.authenticated_download_size,
      "callback_addr": self.callback_addr,
      "usable_for_authenticated_ram_exec": False,
    }


@dataclass(frozen=True)
class PayloadGeometryContract:
  """Geometry baked into a committed authenticated payload fixture."""
  name: str
  size: int
  callback_addr: int
  load_addr: int
  evidence: str

  def validate_geometry(self, geometry: RamExecGeometry) -> None:
    geometry.validate()
    if geometry.size != self.size:
      raise RamExecGeometryError(
        f"payload {self.name} is {self.size:#x} bytes but geometry requires {geometry.size:#x}"
      )
    if geometry.load_addr != self.load_addr:
      raise RamExecGeometryError(
        f"payload {self.name} is authenticated for load {self.load_addr:#010x}, not {geometry.load_addr:#010x}"
      )
    if geometry.callback_addr != self.callback_addr:
      raise RamExecGeometryError(
        f"payload {self.name} callback is {self.callback_addr:#010x}, not {geometry.callback_addr:#010x}"
      )
    if geometry.callback_addr != geometry.load_addr:
      raise RamExecGeometryError(
        "current payload contract requires callback address to equal the authenticated load base"
      )


# Cross-vehicle evidence establishes this exact bootloader download/verify/callback geometry on
# multiple B4/F3/F4 EPS calibrations and, now, direct owner-side H/F range-payload acquisitions.
# These are exact software IDs, never a prefix rule. Exact encrypted-fixture acceptance remains a
# separate gate in bootstrap_profile.py.
COMMUNITY_B4_F3F4_RAM_EXEC = RamExecGeometry(
  name="cross-variant-authenticated-ram-exec",
  load_addr=0xFEBF0000,
  size=0x1000,
  callback_addr=0xFEBF0000,
  target_f181=frozenset({
    "8965B4209000",
    "8965B4233100",
    "8965B4509100",
    "8965B4514000",
    "8965F3401200",
    "8965F4207000",
    "8965F4201000",
    "8965H1202000",
    "8965F1208000",
  }),
  evidence=("SECOC-024/028/063 external-source B4/F3/F4 geometry plus KEYLESS-018/VAR-003/039 " +
            "observed H/F authenticated-RAM range-payload execution"),
)

# Backwards-compatible name retained for callers/tests that refer specifically to the older
# Willem RAM-key-table subset. Its object identity is now the broader boot-geometry evidence;
# extractor.APPLICATION_VERSIONS remains the narrow legacy key-table allow-list.
LEGACY_8965B4_RAM_EXEC = COMMUNITY_B4_F3F4_RAM_EXEC

# The analyzed 4512000 image independently verifies the same 4 KiB authenticated
# download/0x10F0/callback geometry. It is a separate profile because its CPU-visible key
# storage differs from the older RAM-table extraction targets.
ANALYZED_8965B4512000_RAM_EXEC = RamExecGeometry(
  name="8965B4512000-authenticated-ram-exec",
  load_addr=0xFEBF0000,
  size=0x1000,
  callback_addr=0xFEBF0000,
  target_f181=frozenset({"8965B4512000"}),
  evidence="firmware-verified 8965B4512000 RequestDownload/0x10F0/callback geometry",
)

# The maintainer's 2026 Camry 8965F3307000 independently proves the same geometry twice:
# owner-side acquisition accepted SecurityAccess, FEBF0000/0x1000 RequestDownload, 0x10F0,
# 0xFF00, and an authenticated 4 KiB range payload; the recovered exact CodeFlash then
# confirmed the same download/routine tables, payload crypto path, and callback slot.
ANALYZED_8965F3307000_RAM_EXEC = RamExecGeometry(
  name="8965F3307000-authenticated-ram-exec",
  load_addr=0xFEBF0000,
  size=0x1000,
  callback_addr=0xFEBF0000,
  target_f181=frozenset({"8965F3307000"}),
  evidence=("maintainer 2026 Camry field acquisition plus exact 8965F3307000 CodeFlash: " +
            "SecurityAccess/RequestDownload/0x10F0/0xFF00/range-payload execution and matching boot tables"),
)

KNOWN_RAM_EXEC_GEOMETRIES = (
  COMMUNITY_B4_F3F4_RAM_EXEC,
  ANALYZED_8965B4512000_RAM_EXEC,
  ANALYZED_8965F3307000_RAM_EXEC,
)

# External yc/newer-Toyota evidence observed code linked/deployed at FEBE0000. It does not
# establish the authenticated bootloader RequestDownload window or callback package, so it
# cannot be passed to ``resolve_ram_exec_geometry``.
NEWER_TOYOTA_FEBE0000_LINKER_OBSERVATION = LinkerVmaObservation(
  name="newer-toyota-febe0000-linker-vma",
  link_vma=0xFEBE0000,
  evidence="external linker/deployment observation; authenticated download/callback geometry unknown",
)

# All committed payload fixtures in TSK use the same post-link package geometry. The
# auto-reset rebuild additionally verifies these fields directly from decrypted plaintext.
COMMITTED_PAYLOAD_CONTRACT = PayloadGeometryContract(
  name="committed-4k-toyota-eps-payloads",
  size=0x1000,
  load_addr=0xFEBF0000,
  callback_addr=0xFEBF0000,
  evidence="committed payload fixture/package contract; callback at +0xFD0 points to FEBF0000",
)


def normalize_f181(value: bytes | bytearray | str) -> str:
  """Normalize UDS F181 payloads/dashboard strings to the primary exact software ID.

  Toyota/Denso F181 appears both as the older one-record shape
  ``01 || record[16]`` and as newer count-prefixed multi-record responses such as the
  Camry's ``02 || 8965F3307000[16] || 8A3113303100[16]``. TSK's bootstrap tables are
  keyed by the primary 8965... application record, never by the concatenated display.
  """
  if isinstance(value, str):
    text = value.strip("\x00 \t\r\n")
    # Identity-map display strings replace the binary count and NUL padding with dots.
    # Prefer an exact 12-character 8965... record when one is present.
    match = re.search(r"8965[A-Za-z0-9]{8}", text)
    if match:
      return match.group(0)
    text = text.strip(".")
    if text.startswith("\x01"):
      text = text[1:]
    if text.startswith("."):
      text = text[1:]
    return text.strip(".\x00 ")

  raw = bytes(value)
  if raw and 1 <= raw[0] <= 8 and len(raw) >= 17:
    record_count = int(raw[0])
    if len(raw) >= 1 + 16 * record_count:
      primary = raw[1:17].rstrip(b"\x00")
      text = primary.decode("ascii", errors="ignore").strip(".\x00 ")
      if text:
        return text

  raw = raw.rstrip(b"\x00")
  if raw.startswith(b"\x01"):
    raw = raw[1:]
  text = raw.decode("ascii", errors="ignore").strip(".\x00 ")
  match = re.search(r"8965[A-Za-z0-9]{8}", text)
  return match.group(0) if match else text


def known_ram_exec_geometry(f181: bytes | bytearray | str) -> RamExecGeometry | None:
  target = normalize_f181(f181)
  for geometry in KNOWN_RAM_EXEC_GEOMETRIES:
    if target in geometry.target_f181:
      return geometry
  return None


def resolve_ram_exec_geometry(
  f181: bytes | bytearray | str,
  *,
  explicit: RamExecGeometry | None = None,
) -> RamExecGeometry:
  """Resolve executable geometry for one exact F181, failing closed otherwise.

  ``explicit`` is the future extension point for a newly evidenced calibration. It must
  itself assert evidenced authenticated-download and callback geometry and must name the
  exact target being operated on. Merely observing a linker VMA cannot satisfy this API.
  A successful result here says nothing about application-retained executable RAM.
  """
  target = normalize_f181(f181)
  known = known_ram_exec_geometry(target)
  if explicit is None:
    if known is None:
      raise RamExecGeometryError(
        f"no authenticated RAM-exec geometry is verified for EPS F181 {target or '<empty>'}"
      )
    known.validate()
    return known

  explicit.validate()
  if target not in explicit.target_f181:
    raise RamExecGeometryError(
      f"explicit RAM-exec geometry {explicit.name} does not cover EPS F181 {target or '<empty>'}"
    )
  return explicit


def build_request_download_data(geometry: RamExecGeometry) -> bytes:
  """Build the exact bootloader RequestDownload data bound to ``geometry``."""
  geometry.validate()
  return b"\x01\x46\x01\x00" + struct.pack("!I", geometry.load_addr) + struct.pack("!I", geometry.size)


def build_verify_routine_data(geometry: RamExecGeometry) -> bytes:
  """Build the exact routine-0x10F0 verification data bound to ``geometry``."""
  geometry.validate()
  return b"\x45\x00" + struct.pack("!I", geometry.load_addr) + struct.pack("!I", geometry.size)


def transfer_chunks(payload: bytes, geometry: RamExecGeometry, *, chunk_size: int = 0x400) -> list[bytes]:
  """Return payload chunks after proving the transferred byte count matches geometry."""
  geometry.validate()
  if len(payload) != geometry.size:
    raise RamExecGeometryError(
      f"payload length {len(payload):#x} does not match RAM-exec geometry size {geometry.size:#x}"
    )
  if chunk_size <= 0:
    raise RamExecGeometryError("transfer chunk size must be positive")
  return [payload[offset:offset + chunk_size] for offset in range(0, len(payload), chunk_size)]
