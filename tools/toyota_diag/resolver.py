"""Toyota GTS-derived vehicle, mounted-ECU routing, and capability resolution.

The universal bundle carries Toyota regional vehicle decisions, install sets, logical
ECU categories, class-0x10D transport routes, literal support-plugin dispatch, and
family support contracts. Implementation availability is kept separate from Toyota
category/vehicle support. Legacy registries remain compatibility fixtures only.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from opendbc.car.uds import MessageTimeoutError, NegativeResponseError, ROUTINE_CONTROL_TYPE
from opendbc.car.vin import VIN_UNKNOWN, get_vin, is_valid_vin

from tools.toyota_diag import registry
from tools.toyota_diag.registry import Profile

P5_SUPPORT_ROOT_DID = 0x0101
READ_DATA_BY_IDENTIFIER = 0x22


class ResolverError(ValueError):
  pass


@dataclass(frozen=True)
class ToyotaRoute:
  category_id: int
  name: str
  generation: int
  phase_type: int
  request_address: int
  request_address_field: int
  address_extension: int
  protocol_info_id: int
  functional_address: int
  transport_kind: str
  controller: str | None

  @property
  def sub_addr(self) -> int | None:
    # Toyota's protocol row carries the address extension explicitly. A nonzero
    # value maps directly to upstream openpilot's existing (tx_addr, sub_addr) transport.
    return self.address_extension or None

  @property
  def endpoint(self) -> tuple[int, int | None]:
    return self.request_address, self.sub_addr

  @property
  def uds_transport_supported(self) -> bool:
    return self.transport_kind in registry.UDS_TRANSPORT_KINDS

  def as_dict(self) -> dict[str, Any]:
    return {
      "category_id": self.category_id,
      "name": self.name,
      "generation": self.generation,
      "phase_type": self.phase_type,
      "request_address": self.request_address,
      "request_address_field": self.request_address_field,
      "address_extension": self.address_extension,
      "transport_kind": self.transport_kind,
      "controller": self.controller,
      "sub_addr": self.sub_addr,
      "protocol_info_id": self.protocol_info_id,
      "functional_address": self.functional_address,
    }


def _vehicle_resolution(profile: Profile) -> dict[str, Any]:
  raw = profile.vehicle_resolution
  if raw is None:
    raise ResolverError("registry supplies no Toyota vehicle_resolution metadata (requires registry v5+)")
  return raw


def _vin11(vin: str) -> bytes:
  if vin == VIN_UNKNOWN or not is_valid_vin(vin):
    raise ResolverError(f"invalid/unavailable VIN {vin!r}")
  return vin[:11].encode("ascii")


def vin_decision_matches(row: dict[str, Any], vin: str, *, category_id: int, phase_type: int) -> bool:
  """Express current CDbVinVehicleDecisionTable::DecisionKey over a structured resolver row."""
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

  The registry identifies the source category and phase rows selected from Toyota's
  current master. This function evaluates the exact VIN wildcard predicate;
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


def route_for_candidate(candidate: dict[str, Any]) -> ToyotaRoute:
  """Validate and materialize Toyota's class-0x10D route for one install candidate."""
  raw = candidate.get("transport_route")
  if not isinstance(raw, dict):
    raise ResolverError(f"category {candidate.get('category_id')} has no Toyota transport_route")
  try:
    category_id = int(candidate["category_id"])
    name = str(candidate.get("name") or f"Category {category_id}")
    generation = int(candidate["generation"])
    phase_type = int(candidate["connection_phase_type"])
    route_phase = int(raw["phase_type"])
    request_address_field = int(raw["request_address"])
    physical_request = raw.get("physical_request_address")
    request_address = int(physical_request) if physical_request is not None else request_address_field
    extension = int(raw["address_extension"])
    protocol_info_id = int(raw["protocol_info_id"])
    functional_address = int(raw["functional_address"])
    transport_kind = str(raw.get("transport_kind") or "legacy-unclassified")
    controller = str(raw["controller"]) if raw.get("controller") else None
  except (KeyError, TypeError, ValueError) as e:
    raise ResolverError(f"malformed Toyota transport route: {candidate!r}") from e
  if phase_type != route_phase:
    raise ResolverError(
      f"category {category_id} install phase 0x{phase_type:02X} disagrees with route phase 0x{route_phase:02X}")
  if request_address < 0:
    raise ResolverError(f"category {category_id} Toyota request address is negative: {request_address}")
  if not 0 <= extension <= 0xFF:
    raise ResolverError(f"category {category_id} Toyota address extension is not one byte: {extension}")
  return ToyotaRoute(
    category_id=category_id, name=name, generation=generation, phase_type=phase_type,
    request_address=request_address, request_address_field=request_address_field, address_extension=extension,
    protocol_info_id=protocol_info_id, functional_address=functional_address,
    transport_kind=transport_kind, controller=controller,
  )


def mount_routes(profile: Profile) -> tuple[tuple[dict[str, Any], ToyotaRoute], ...]:
  """Return mount candidates whose generation has an implemented exact Toyota route."""
  _vehicle_resolution(profile)
  rows = profile.mount_candidates()
  if not rows:
    raise ResolverError("vehicle_resolution.mount.candidates is empty")
  return tuple((candidate, route_for_candidate(candidate)) for candidate in rows if isinstance(candidate.get("transport_route"), dict))


def lookup_mount_candidate(profile: Profile, ref: str | int) -> tuple[dict[str, Any], ToyotaRoute]:
  """Resolve a Toyota logical category by category ID, profile ECU alias, name, or DDB name."""
  rows = mount_routes(profile)
  category_id = None
  if isinstance(ref, int):
    category_id = ref
  else:
    text = ref.strip()
    try:
      # Decimal is the natural Toyota category notation; explicit 0x is also accepted.
      category_id = int(text, 0)
    except ValueError:
      category_id = None
    if category_id is None:
      try:
        spec = profile.lookup_ecu(text)
      except registry.RegistryError:
        spec = None
      if spec is not None and spec.category_id is not None:
        category_id = spec.category_id
      else:
        needle = text.casefold()
        matches = [
          pair for pair in rows
          if needle in {
            str(pair[0].get("name") or "").casefold(),
            str(pair[0].get("database") or "").casefold(),
          }
        ]
        if len(matches) == 1:
          return matches[0]
        if not matches:
          raise ResolverError(f"no Toyota mount category matches {ref!r}")
        raise ResolverError(f"ambiguous Toyota mount category {ref!r}")
  matches = [pair for pair in rows if pair[1].category_id == category_id]
  if len(matches) == 1:
    return matches[0]
  if not matches:
    raise ResolverError(f"no Toyota mount category matches {ref!r}")
  raise ResolverError(f"ambiguous Toyota mount category {ref!r}")


def category_metadata(profile: Profile, category_id: int) -> dict[str, Any] | None:
  """Return Toyota master category metadata without requiring a decoded catalog shard."""
  if profile.database is not None and profile.region is not None:
    categories = profile.database.region_index(profile.region).get("categories")
    row = categories.get(str(category_id)) if isinstance(categories, dict) else None
    if isinstance(row, dict):
      return row
  for candidate in profile.mount_candidates():
    if int(candidate.get("category_id", -1)) == category_id:
      return candidate
  return None


def support_family(profile: Profile, category_id: int) -> str | None:
  """Toyota DLL-table-selected support family; generation fallback is legacy-fixture-only."""
  row = category_metadata(profile, category_id)
  value = row.get("support_family") if isinstance(row, dict) else None
  if value:
    return str(value).casefold()
  # Registry v5/v6 predates literal DLL-family metadata. Preserve it as a compatibility
  # fixture without allowing this inference to become authority for universal bundles.
  if profile.database is None:
    candidate = next((item for item in profile.mount_candidates() if int(item.get("category_id", -1)) == category_id), None)
    raw = profile.session_control or {}
    eligible = raw.get("eligible_generation_low5")
    if isinstance(candidate, dict) and isinstance(eligible, list):
      generation = int(candidate.get("generation", -1)) & 0x1F
      values = {registry.parse_int(item, "session_control.eligible_generation_low5") for item in eligible}
      if generation in values:
        return "p5"
  return None


def support_mode(profile: Profile, category_id: int) -> str | None:
  """Toyota family-local support-list mode, distinct from the shared plugin family."""
  row = category_metadata(profile, category_id)
  value = row.get("support_mode") if isinstance(row, dict) else None
  if value:
    return str(value).casefold()
  family = support_family(profile, category_id)
  if profile.database is None and family == "p5":
    # Legacy Camry v6 predates the family-local mode export. Its retained generation-20
    # Toyota categories were built through the ordinary C8 path; do not generalize this
    # compatibility inference to universal bundles or other generation modes.
    candidate = next((item for item in profile.mount_candidates() if int(item.get("category_id", -1)) == category_id), None)
    if isinstance(candidate, dict):
      generation = int(candidate.get("generation", -1))
      if (generation & 0x1F) == 0x14 and (generation & 0xE0) == 0:
        return "p5-standard"
  return family


def support_contract(profile: Profile, family: str) -> dict[str, Any] | None:
  contracts = None
  if profile.vehicle_resolution is not None:
    contracts = profile.vehicle_resolution.get("support_contracts")
  if not isinstance(contracts, dict) and profile.database is not None:
    contracts = profile.database.index.get("support_contracts")
  row = contracts.get(family.casefold()) if isinstance(contracts, dict) else None
  return row if isinstance(row, dict) else None



def analyze_support_bitmap(base: int, bitmap: bytes, shift: int) -> list[int]:
  """Express ordinary-P5 CCmdSupportDataIdList::AnalyzeFrameData exactly.

  Root calls use shift=8 and retain the resulting xx00 IDs. Member calls use
  shift=0, add one, and skip byte31/bit7 because it aliases the next xx00 root.
  """
  out: list[int] = []
  for byte_index, value in enumerate(bitmap[:32]):
    for bit_index in range(8):
      if not value & (0x80 >> bit_index):
        continue
      if shift:
        out.append((base + ((byte_index * 8 + bit_index) << shift)) & 0xFFFF)
      else:
        if byte_index == 31 and bit_index == 7:
          continue
        out.append((base + 1 + byte_index * 8 + bit_index) & 0xFFFF)
  return out


def analyze_p6_support_bitmap(base: int, bitmap: bytes) -> list[int]:
  """Express CCmdSupportDataIdListP6::AnalyzeFrameData for the shift-0 calls used by DID/RID support."""
  out: list[int] = []
  for byte_index, value in enumerate(bitmap[:32]):
    for bit_index in range(8):
      if value & (0x80 >> bit_index):
        out.append((base + byte_index * 8 + bit_index) & 0xFFFF)
  return out


def _bitmap_has(bitmap: bytes, bit_index: int) -> bool:
  if bit_index < 0 or bit_index >= 256:
    return False
  byte_index, within = divmod(bit_index, 8)
  return byte_index < min(len(bitmap), 32) and bool(bitmap[byte_index] & (0x80 >> within))


@dataclass
class P5DidSupportResolver:
  """Lazy ordinary-Toyota P5 DID support resolver using the C8 two-level bitmap."""
  client: Any
  root_did: int = P5_SUPPORT_ROOT_DID
  excluded_groups: frozenset[int] = frozenset({0xF300, 0xFD00})
  _root: bytes | None = None
  _groups: dict[int, bytes] | None = None

  @classmethod
  def from_profile(cls, profile: Profile, client: Any) -> P5DidSupportResolver:
    raw = support_contract(profile, "p5")
    if raw is None:
      raw = _vehicle_resolution(profile).get("p5_support")
    did_root = raw.get("did_root") if isinstance(raw, dict) else None
    if not isinstance(did_root, dict):
      raise ResolverError("vehicle_resolution.p5_support.did_root is missing")
    request = registry.parse_bytes(did_root.get("request"), "vehicle_resolution.p5_support.did_root.request")
    if len(request) != 3 or request[0] != READ_DATA_BY_IDENTIFIER:
      raise ResolverError(f"P5 DID support root request is not 22xxxx: {request.hex()}")
    if str(did_root.get("positive_sid")).lower() not in {"0x62", "62"}:
      raise ResolverError("P5 DID support root positive SID is not 0x62")
    standard = raw.get("standard_did") if isinstance(raw, dict) else None
    excluded = {0xF300, 0xFD00}
    if isinstance(standard, dict) and isinstance(standard.get("selector_excluded"), list):
      excluded = {registry.parse_int(value, "support_contracts.p5.standard_did.selector_excluded")
                  for value in standard["selector_excluded"]}
    return cls(client=client, root_did=int.from_bytes(request[1:3], "big"), excluded_groups=frozenset(excluded))

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
    if not _bitmap_has(self.root_bitmap(), group >> 8) or group in self.excluded_groups:
      return b""
    if group not in self.group_cache:
      self.group_cache[group] = bytes(self.client.read_data_by_identifier(group))
    return self.group_cache[group]

  def supports(self, did: int) -> bool:
    if not 0 <= did <= 0xFFFF:
      raise ResolverError(f"DID out of range: {did:#x}")
    group = did & 0xFF00
    if not _bitmap_has(self.root_bitmap(), group >> 8):
      return False
    low = did & 0xFF
    if low == 0:
      return True  # Toyota retains root xx00 IDs in the enabled-ID list.
    if group in self.excluded_groups:
      return False
    return _bitmap_has(self.group_bitmap(group), low - 1)

  def supported_dids(self) -> tuple[int, ...]:
    out: list[int] = []
    for group in self.supported_groups():
      out.append(group)
      if group not in self.excluded_groups:
        out.extend(analyze_support_bitmap(group, self.group_bitmap(group), 0))
    return tuple(dict.fromkeys(out))


@dataclass
class P6DidSupportResolver:
  """Lazy P6 DID support resolver recovered from CCmdSupportDataIdListP6."""
  client: Any
  root_did: int = 0xA100
  excluded_selectors: frozenset[int] = frozenset({0xA1FD, 0xA1FE})
  _root: bytes | None = None
  _selectors: dict[int, bytes] | None = None

  @classmethod
  def from_profile(cls, profile: Profile, client: Any) -> P6DidSupportResolver:
    raw = support_contract(profile, "p6")
    did_root = raw.get("did_root") if isinstance(raw, dict) else None
    if not isinstance(did_root, dict):
      raise ResolverError("support_contracts.p6.did_root is missing")
    request = registry.parse_bytes(did_root.get("request"), "support_contracts.p6.did_root.request")
    if len(request) != 3 or request[0] != READ_DATA_BY_IDENTIFIER:
      raise ResolverError(f"P6 DID support root request is not 22xxxx: {request.hex()}")
    if str(did_root.get("positive_sid")).lower() not in {"0x62", "62"}:
      raise ResolverError("P6 DID support root positive SID is not 0x62")
    root = registry.parse_int(did_root.get("root_base", int.from_bytes(request[1:], "big")),
                              "support_contracts.p6.did_root.root_base")
    excluded = {registry.parse_int(value, "support_contracts.p6.did_root.selector_excluded")
                for value in did_root.get("selector_excluded", [])}
    return cls(client=client, root_did=root, excluded_selectors=frozenset(excluded))

  @property
  def selector_cache(self) -> dict[int, bytes]:
    if self._selectors is None:
      self._selectors = {}
    return self._selectors

  def root_bitmap(self) -> bytes:
    if self._root is None:
      self._root = bytes(self.client.read_data_by_identifier(self.root_did))
    return self._root

  def supported_groups(self) -> tuple[int, ...]:
    # Retain the CLI/API name for symmetry with P5; these are P6 A1nn selectors.
    return tuple(analyze_p6_support_bitmap(self.root_did, self.root_bitmap()))

  def selector_bitmap(self, selector: int) -> bytes:
    if not self.root_did <= selector <= self.root_did + 0xFF:
      raise ResolverError(f"P6 DID selector must be A1nn, got 0x{selector:04X}")
    if not _bitmap_has(self.root_bitmap(), selector - self.root_did) or selector in self.excluded_selectors:
      return b""
    if selector not in self.selector_cache:
      self.selector_cache[selector] = bytes(self.client.read_data_by_identifier(selector))
    return self.selector_cache[selector]

  def supports(self, did: int) -> bool:
    if not 0 <= did <= 0xFFFF:
      raise ResolverError(f"DID out of range: {did:#x}")
    if self.root_did <= did <= self.root_did + 0xFF and _bitmap_has(self.root_bitmap(), did - self.root_did):
      return True
    selector = self.root_did + (did >> 8)
    if selector > self.root_did + 0xFF or not _bitmap_has(self.root_bitmap(), selector - self.root_did):
      return False
    if selector in self.excluded_selectors:
      return False
    return _bitmap_has(self.selector_bitmap(selector), did & 0xFF)

  def supported_dids(self) -> tuple[int, ...]:
    out: list[int] = list(self.supported_groups())
    for selector in self.supported_groups():
      if selector in self.excluded_selectors:
        continue
      base = (selector & 0xFF) << 8
      out.extend(analyze_p6_support_bitmap(base, self.selector_bitmap(selector)))
    return tuple(dict.fromkeys(out))


@dataclass
class P6RidSupportResolver:
  """Lazy P6 RID support resolver recovered from CCmdSupportDataIdListP6."""
  client: Any
  root_rid: int = 0xD100
  excluded_selectors: frozenset[int] = frozenset({0xD1F0, 0xD1FE})
  _root: bytes | None = None
  _selectors: dict[int, bytes] | None = None

  @classmethod
  def from_profile(cls, profile: Profile, client: Any) -> P6RidSupportResolver:
    raw = support_contract(profile, "p6")
    routine_root = raw.get("routine_root") if isinstance(raw, dict) else None
    if not isinstance(routine_root, dict):
      raise ResolverError("support_contracts.p6.routine_root is missing")
    request = registry.parse_bytes(routine_root.get("request"), "support_contracts.p6.routine_root.request")
    if len(request) != 4 or request[:2] != bytes([0x31, int(ROUTINE_CONTROL_TYPE.START)]):
      raise ResolverError(f"P6 RID support root request is not 3101xxxx: {request.hex()}")
    if str(routine_root.get("positive_sid")).lower() not in {"0x71", "71"}:
      raise ResolverError("P6 RID support root positive SID is not 0x71")
    root = registry.parse_int(routine_root.get("root_base", int.from_bytes(request[2:], "big")),
                              "support_contracts.p6.routine_root.root_base")
    excluded = {registry.parse_int(value, "support_contracts.p6.routine_root.selector_excluded")
                for value in routine_root.get("selector_excluded", [])}
    return cls(client=client, root_rid=root, excluded_selectors=frozenset(excluded))

  @property
  def selector_cache(self) -> dict[int, bytes]:
    if self._selectors is None:
      self._selectors = {}
    return self._selectors

  def _request(self, rid: int) -> bytes:
    return bytes(self.client.routine_control(ROUTINE_CONTROL_TYPE.START, rid))

  def root_bitmap(self) -> bytes:
    if self._root is None:
      self._root = self._request(self.root_rid)
    return self._root

  def supported_groups(self) -> tuple[int, ...]:
    # API symmetry with DID support; these are P6 D1nn selector RIDs.
    return tuple(analyze_p6_support_bitmap(self.root_rid, self.root_bitmap()))

  def selector_bitmap(self, selector: int) -> bytes:
    if not self.root_rid <= selector <= self.root_rid + 0xFF:
      raise ResolverError(f"P6 RID selector must be D1nn, got 0x{selector:04X}")
    if not _bitmap_has(self.root_bitmap(), selector - self.root_rid) or selector in self.excluded_selectors:
      return b""
    if selector not in self.selector_cache:
      self.selector_cache[selector] = self._request(selector)
    return self.selector_cache[selector]

  def supports(self, rid: int) -> bool:
    if not 0 <= rid <= 0xFFFF:
      raise ResolverError(f"RID out of range: {rid:#x}")
    if self.root_rid <= rid <= self.root_rid + 0xFF and _bitmap_has(self.root_bitmap(), rid - self.root_rid):
      return True
    selector = self.root_rid + (rid >> 8)
    if selector > self.root_rid + 0xFF or not _bitmap_has(self.root_bitmap(), selector - self.root_rid):
      return False
    if selector in self.excluded_selectors:
      return False
    return _bitmap_has(self.selector_bitmap(selector), rid & 0xFF)

  def supported_rids(self) -> tuple[int, ...]:
    out: list[int] = list(self.supported_groups())
    for selector in self.supported_groups():
      if selector in self.excluded_selectors:
        continue
      base = (selector & 0xFF) << 8
      out.extend(analyze_p6_support_bitmap(base, self.selector_bitmap(selector)))
    return tuple(dict.fromkeys(out))


def rid_support_resolver(profile: Profile, category_id: int, client: Any) -> P6RidSupportResolver:
  """Instantiate Toyota's exact RID support executor when recovered."""
  mode = support_mode(profile, category_id)
  if mode == "p6-standard":
    return P6RidSupportResolver.from_profile(profile, client)
  family = support_family(profile, category_id) or "unresolved"
  raise ResolverError(
    f"Toyota category {category_id} selects support family {family}, mode {mode or 'unresolved'}; "
    + "that exact RID support-list executor is not yet recovered in this runtime")


def did_support_resolver(profile: Profile, category_id: int, client: Any) -> P5DidSupportResolver | P6DidSupportResolver:
  """Instantiate the exact Toyota DID support executor selected for this category."""
  mode = support_mode(profile, category_id)
  if mode == "p5-standard":
    return P5DidSupportResolver.from_profile(profile, client)
  if mode == "p6-standard":
    return P6DidSupportResolver.from_profile(profile, client)
  family = support_family(profile, category_id) or "unresolved"
  raise ResolverError(
    f"Toyota category {category_id} selects support family {family}, mode {mode or 'unresolved'}; "
    + "that exact DID support-list executor is not yet recovered in this runtime")


def _response_probe(client: Any, did: int) -> tuple[str, bytes | None, str | None]:
  try:
    return "positive", bytes(client.read_data_by_identifier(did)), None
  except NegativeResponseError as e:
    # A valid UDS negative response still proves this transport endpoint answered.
    return "negative", None, str(e)
  except MessageTimeoutError as e:
    return "timeout", None, str(e)


def _support_root_did(profile: Profile, family: str) -> int | None:
  contract = support_contract(profile, family)
  if contract is None and family == "p5" and profile.database is None:
    legacy = profile.vehicle_resolution or {}
    candidate = legacy.get("p5_support")
    contract = candidate if isinstance(candidate, dict) else None
  root = contract.get("did_root") if isinstance(contract, dict) else None
  if not isinstance(root, dict):
    return None
  try:
    request = registry.parse_bytes(root.get("request"), f"support_contracts.{family}.did_root.request")
  except registry.RegistryError:
    return None
  if len(request) != 3 or request[0] != READ_DATA_BY_IDENTIFIER:
    return None
  return int.from_bytes(request[1:], "big")


def probe_mount_candidates(profile: Profile, client_factory) -> list[dict[str, Any]]:
  """Probe Toyota install candidates only where the exact selected support executor is implemented.

  Every Toyota candidate remains represented. `probe_unavailable` means this runtime
  does not yet reproduce that category's Toyota family-local support executor; it is
  never a statement that the ECU/generation is unsupported or absent.
  """
  _vehicle_resolution(profile)
  result: list[dict[str, Any]] = []
  endpoint_cache: dict[tuple[int, int | None, str, int], dict[str, Any]] = {}
  for candidate in profile.mount_candidates():
    row = dict(candidate)
    category_id = int(candidate.get("category_id", -1))
    family = support_family(profile, category_id)
    mode = support_mode(profile, category_id)
    row["support_family"] = family
    row["support_mode"] = mode
    if not isinstance(candidate.get("transport_route"), dict):
      row.update(live_state="route_unresolved", transport_responded=None, probe_available=False,
                 support_root=None, supported_group_count=None,
                 probe_error="Toyota class-0x10D route is not resolved in this corpus")
      result.append(row)
      continue
    route = route_for_candidate(candidate)
    if mode not in {"p5-standard", "p6-standard"}:
      row.update(live_state="probe_unavailable", transport_responded=None, probe_available=False,
                 support_root=None, supported_group_count=None,
                 probe_error=(
                   f"Toyota support family {family or 'unresolved'}, mode {mode or 'unresolved'} is known, "
                   + "but that exact live support executor is not recovered in this runtime"))
      result.append(row)
      continue
    if not route.uds_transport_supported:
      row.update(live_state="probe_unavailable", transport_responded=None, probe_available=False,
                 support_root=None, supported_group_count=None,
                 probe_error=(f"Toyota route uses {route.transport_kind} ({route.controller or 'controller unresolved'}); "
                              + "this Panda UDS runtime does not implement that transport"))
      result.append(row)
      continue
    root_did = _support_root_did(profile, family or "")
    if root_did is None:
      row.update(live_state="probe_unavailable", transport_responded=None, probe_available=False,
                 support_root=None, supported_group_count=None,
                 probe_error=f"Toyota support mode {mode} has no recovered DID root contract")
      result.append(row)
      continue

    endpoint_key = (route.request_address, route.sub_addr, mode, root_did)
    if endpoint_key not in endpoint_cache:
      client = client_factory(route.request_address, route.sub_addr)
      root_state, root_payload, root_error = _response_probe(client, root_did)
      if root_payload is not None:
        if mode == "p5-standard":
          group_count = len(analyze_support_bitmap(0, root_payload, 8))
        else:
          group_count = len(analyze_p6_support_bitmap(root_did, root_payload))
      else:
        group_count = None
      if root_state in {"positive", "negative"}:
        state = {
          "live_state": "responding",
          "transport_responded": True,
          "probe_available": True,
          "support_root": root_state == "positive",
          "supported_group_count": group_count,
          "support_error": root_error,
          "support_root_did": root_did,
        }
      else:
        state = {
          "live_state": "no_response",
          "transport_responded": False,
          "probe_available": True,
          "support_root": None,
          "supported_group_count": None,
          "support_error": root_error,
          "support_root_did": root_did,
        }
      endpoint_cache[endpoint_key] = state
    row.update(endpoint_cache[endpoint_key])
    result.append(row)
  return result
