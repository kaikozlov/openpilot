#!/usr/bin/env python3
"""Evidence-bound authenticated RAM-execution geometry for Toyota EPS tooling.

A programming-session handoff, a writable RAM address, or a shellcode linker VMA is not
sufficient evidence that an EPS accepts an authenticated RequestDownload at that address.
The bootloader payload path couples four things that must agree:

* the RequestDownload destination;
* the transferred payload length;
* the 0x10F0 verification address/length; and
* the callback address embedded in the authenticated payload package.

Only calibrations with evidence for that complete contract resolve automatically here.
Unknown calibrations fail closed.  A future non-default geometry can be represented only
as an explicitly verified ``RamExecGeometry``; the separate linker-VMA observation type is
intentionally not accepted by the resolver.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
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


# Historical field-supported Willem/TSKM targets. These are intentionally exact F181s,
# not a broad 8965B4 prefix rule.
LEGACY_8965B4_RAM_EXEC = RamExecGeometry(
  name="legacy-8965B4-authenticated-ram-exec",
  load_addr=0xFEBF0000,
  size=0x1000,
  callback_addr=0xFEBF0000,
  target_f181=frozenset({
    "8965B4209000",  # 2021 RAV4 Prime
    "8965B4233100",  # 2023 RAV4 Prime
    "8965B4509100",  # 2021 Sienna fixture used by current source audit
  }),
  evidence="field-supported Willem/TSKM 8965B4 transfer fixtures",
)

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

KNOWN_RAM_EXEC_GEOMETRIES = (LEGACY_8965B4_RAM_EXEC, ANALYZED_8965B4512000_RAM_EXEC)

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
  """Normalize UDS F181 payloads and dashboard strings to an exact application ID."""
  if isinstance(value, str):
    text = value.strip(".\x00 \t\r\n")
    if text.startswith("\x01"):
      text = text[1:]
    # Dashboard strings can contain a leading display dot for the binary format byte.
    if text.startswith("."):
      text = text[1:]
    return text.strip(".\x00 ")

  raw = bytes(value).rstrip(b"\x00")
  if raw.startswith(b"\x01"):
    raw = raw[1:]
  return raw.decode("ascii", errors="ignore").strip(".\x00 ")


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
  itself assert verified authenticated-download and callback geometry and must name the
  exact target being operated on. Merely observing a linker VMA cannot satisfy this API.
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
