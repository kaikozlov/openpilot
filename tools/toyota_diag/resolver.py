"""Toyota GTS-derived vehicle, mounted-ECU, and current-P5 capability resolution.

Registry v5 carries a clean representation of the current GTS+ resolver recovered in
`ghidra_rh850_analysis`: VIN decision rows, install-set/mount candidates, and the
GetSupportP5 DID bitmap contract.  This module interprets that metadata without
shipping or emulating Toyota binaries.

The live Comma transport cannot reproduce Toyota's category-aware J2534 connection
object for gateway-shared logical ECUs.  Consequently live mount probing is exact only
about what it actually observes: a response from a registry-supplied direct endpoint
proves that transport endpoint is present; no response is reported as `no_response`,
not as proof that a Toyota logical ECU is absent.  Candidates without a validated
`direct_address` remain `not_directly_routed` rather than being collapsed onto a
shared CAN ID.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from opendbc.car.uds import MessageTimeoutError, NegativeResponseError
from opendbc.car.vin import VIN_UNKNOWN, get_vin, is_valid_vin

from tools.toyota_diag import registry
from tools.toyota_diag.registry import Profile

P5_SUPPORT_ROOT_DID = 0x0101
CURRENT_SESSION_DID = 0xF186
READ_DATA_BY_IDENTIFIER = 0x22


class ResolverError(ValueError):
  pass


def _vehicle_resolution(profile: Profile) -> dict[str, Any]:
  raw = profile.vehicle_resolution
  if raw is None:
    raise ResolverError("registry supplies no Toyota vehicle_resolution metadata (requires registry v5)")
  return raw


def _vin11(vin: str) -> bytes:
  if vin == VIN_UNKNOWN or not is_valid_vin(vin):
    raise ResolverError(f"invalid/unavailable VIN {vin!r}")
  return vin[:11].encode("ascii")


def vin_decision_matches(row: dict[str, Any], vin: str, *, category_id: int, phase_type: int) -> bool:
  """Express current CDbVinVehicleDecisionTable::DecisionKey over a v5 row."""
  vin11 = _vin11(vin)
  try:
    if int(row["category_id"]) != category_id or int(row["phase_type"]) != phase_type:
      return False
    flags = int(row["flags"])
    prefix = bytes.fromhex(str(row["vin_prefix_hex"]))
  except (KeyError, TypeError, ValueError) as e:
    raise ResolverError(f"malformed VIN decision row: {row!r}") from e
  if len(prefix) != 11:
    raise ResolverError(f"VIN decision prefix must be 11 bytes, got {len(prefix)}")
  return all((flags & (1 << index)) or prefix[index] == vin11[index] for index in range(11))


def resolve_profile_vin(profile: Profile, vin: str) -> dict[str, Any] | None:
  """Resolve one bundled profile's Toyota VIN-decision rows.

  The v5 profile already identifies the source category and phase rows selected from
  Toyota's current master.  This function evaluates the exact VIN wildcard predicate;
  live endpoint/capability observations are a separate stage below.
  """
  raw = _vehicle_resolution(profile)
  decision = raw.get("vin_decision")
  if not isinstance(decision, dict):
    raise ResolverError("vehicle_resolution.vin_decision must be an object")
  rows = decision.get("rows")
  if not isinstance(rows, list) or not rows:
    raise ResolverError("vehicle_resolution.vin_decision.rows must be non-empty")
  source_category = registry.parse_int(decision.get("source_category_id"), "vehicle_resolution.vin_decision.source_category_id")
  source_mount = [row for row in profile.mount_candidates() if int(row.get("category_id", -1)) == source_category]
  source_phases = {registry.parse_int(row.get("connection_phase_type"), "mount candidate connection_phase_type") for row in source_mount}
  if len(source_phases) != 1:
    raise ResolverError(f"source category {source_category} has ambiguous/missing mount phase types: {sorted(source_phases)}")
  source_phase = next(iter(source_phases))
  matches = [row for row in rows if vin_decision_matches(row, vin, category_id=source_category, phase_type=source_phase)]
  if not matches:
    return None
  vehicle_types = {registry.parse_int(row.get("vehicle_type"), "VIN decision vehicle_type") for row in matches}
  if vehicle_types != {registry.parse_int(raw.get("vehicle_type"), "vehicle_resolution.vehicle_type")}:
    raise ResolverError(f"VIN decision rows disagree with profile vehicle type: {sorted(vehicle_types)}")
  return {
    "profile": profile.name,
    "vehicle": profile.vehicle,
    "vin": vin,
    "vehicle_type": int(raw["vehicle_type"]),
    "vehicle_name": str(raw["vehicle_name"]),
    "install_set_ids": list(raw.get("install_set_ids") or []),
    "source_category_id": source_category,
    "source_phase_type": source_phase,
    "decision_rows": matches,
  }


def read_vehicle_vin(can_recv, can_send, bus: int, *, timeout: float = 0.1, retry: int = 2) -> dict[str, Any]:
  """Run openpilot's ordinary VIN query once on the selected diagnostic bus."""
  rx_address, rx_bus, vin = get_vin(can_recv, can_send, (bus,), timeout=timeout, retry=retry)
  if vin == VIN_UNKNOWN or not is_valid_vin(vin):
    raise ResolverError("Toyota vehicle resolution could not obtain a valid 17-character VIN")
  return {"vin": vin, "rx_address": rx_address, "rx_bus": rx_bus}


def analyze_support_bitmap(base: int, bitmap: bytes, shift: int) -> list[int]:
  """Express CCmdSupportDataIdList::AnalyzeFrameData exactly (MSB-first, max 32 bytes)."""
  out: list[int] = []
  for byte_index, value in enumerate(bitmap[:32]):
    for bit_index in range(8):
      if not value & (0x80 >> bit_index):
        continue
      if shift:
        out.append((base + ((byte_index * 8 + bit_index) << shift)) & 0xFFFF)
      else:
        # byte31 bit7 would be xx100, i.e. the following group's xx00 marker.
        if byte_index == 31 and bit_index == 7:
          continue
        out.append((base + 1 + byte_index * 8 + bit_index) & 0xFFFF)
  return out


def _bitmap_has(bitmap: bytes, bit_index: int) -> bool:
  if bit_index < 0 or bit_index >= 256:
    return False
  byte_index, within = divmod(bit_index, 8)
  return byte_index < min(len(bitmap), 32) and bool(bitmap[byte_index] & (0x80 >> within))


@dataclass
class P5DidSupportResolver:
  """Lazy current-P5 DID support resolver using Toyota's C8 two-level bitmap."""
  client: Any
  root_did: int = P5_SUPPORT_ROOT_DID
  _root: bytes | None = None
  _groups: dict[int, bytes] | None = None

  @classmethod
  def from_profile(cls, profile: Profile, client: Any) -> P5DidSupportResolver:
    raw = _vehicle_resolution(profile).get("p5_support")
    did_root = raw.get("did_root") if isinstance(raw, dict) else None
    if not isinstance(did_root, dict):
      raise ResolverError("vehicle_resolution.p5_support.did_root is missing")
    request = registry.parse_bytes(did_root.get("request"), "vehicle_resolution.p5_support.did_root.request")
    if len(request) != 3 or request[0] != READ_DATA_BY_IDENTIFIER:
      raise ResolverError(f"P5 DID support root request is not 22xxxx: {request.hex()}")
    if str(did_root.get("positive_sid")).lower() not in {"0x62", "62"}:
      raise ResolverError("P5 DID support root positive SID is not 0x62")
    return cls(client=client, root_did=int.from_bytes(request[1:3], "big"))

  @property
  def group_cache(self) -> dict[int, bytes]:
    if self._groups is None:
      self._groups = {}
    return self._groups

  def root_bitmap(self) -> bytes:
    if self._root is None:
      self._root = bytes(self.client.read_data_by_identifier(self.root_did))
    return self._root

  def supported_groups(self) -> tuple[int, ...]:
    return tuple(analyze_support_bitmap(0, self.root_bitmap(), 8))

  def group_bitmap(self, group: int) -> bytes:
    if group & 0xFF or not 0 <= group <= 0xFF00:
      raise ResolverError(f"P5 DID support group must be xx00, got 0x{group:04X}")
    if not _bitmap_has(self.root_bitmap(), group >> 8):
      return b""
    if group not in self.group_cache:
      self.group_cache[group] = bytes(self.client.read_data_by_identifier(group))
    return self.group_cache[group]

  def supports(self, did: int) -> bool:
    if not 0 <= did <= 0xFFFF:
      raise ResolverError(f"DID out of range: {did:#x}")
    low = did & 0xFF
    if low == 0:
      return False  # xx00 is the group query marker, not an enumerated member DID.
    group = did & 0xFF00
    if not _bitmap_has(self.root_bitmap(), group >> 8):
      return False
    return _bitmap_has(self.group_bitmap(group), low - 1)

  def supported_dids(self) -> tuple[int, ...]:
    out: list[int] = []
    for group in self.supported_groups():
      out.extend(analyze_support_bitmap(group, self.group_bitmap(group), 0))
    return tuple(out)


def _response_probe(client: Any, did: int) -> tuple[str, bytes | None, str | None]:
  try:
    return "positive", bytes(client.read_data_by_identifier(did)), None
  except NegativeResponseError as e:
    # A valid UDS negative response still proves this transport endpoint answered.
    return "negative", None, str(e)
  except MessageTimeoutError as e:
    return "timeout", None, str(e)


def probe_mount_candidates(profile: Profile, client_factory) -> list[dict[str, Any]]:
  """Probe the v5 Toyota logical mount candidates reachable through known direct endpoints.

  A direct endpoint response is positive evidence of transport presence.  `no_response`
  remains an observation, not a claim that the logical Toyota category is absent.
  Gateway/shared candidates with no validated direct endpoint are retained distinctly.
  """
  _vehicle_resolution(profile)  # fail closed for pre-v5 registries
  rows = profile.mount_candidates()
  if not rows:
    raise ResolverError("vehicle_resolution.mount.candidates is empty")

  result: list[dict[str, Any]] = []
  address_cache: dict[int, dict[str, Any]] = {}
  for candidate in rows:
    row = dict(candidate)
    address = row.get("direct_address")
    if address is None:
      row.update(live_state="not_directly_routed", transport_responded=None,
                 support_root=None, supported_group_count=None)
      result.append(row)
      continue
    address = int(address)
    if address not in address_cache:
      client = client_factory(address)
      support = P5DidSupportResolver.from_profile(profile, client)
      root_state, root_payload, root_error = _response_probe(client, support.root_did)
      if root_state in {"positive", "negative"}:
        state = {
          "live_state": "responding",
          "transport_responded": True,
          "support_root": root_state == "positive",
          "supported_group_count": len(analyze_support_bitmap(0, root_payload or b"", 8)) if root_payload is not None else None,
          "support_error": root_error,
        }
      else:
        # F186 is the separately recovered current-P5 session-state poll.  It is
        # a read-only fallback for endpoint presence if the support root times out.
        session_state, _, session_error = _response_probe(client, CURRENT_SESSION_DID)
        responded = session_state in {"positive", "negative"}
        state = {
          "live_state": "responding" if responded else "no_response",
          "transport_responded": responded,
          "support_root": None,
          "supported_group_count": None,
          "support_error": root_error,
          "fallback_error": session_error,
        }
      address_cache[address] = state
    row.update(address_cache[address])
    result.append(row)
  return result
