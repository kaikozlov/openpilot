"""Loader/query helpers for the derived Toyota diagnostic database.

The default artifact is generated from current Toyota GTS+ regional masters. It
contains clean vehicle/install/category/route/capability metadata and compressed
current-P5 catalog shards; no Toyota binary or DDB payload is shipped. A legacy
Camry-specific JSON remains available only for compatibility and retained evidence.
"""
from __future__ import annotations

import json
import math
import re
import zipfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).with_name("data")
DEFAULT_REGISTRY = DATA_DIR / "toyota_current_diag.zip"
LEGACY_CAMRY_REGISTRY = DATA_DIR / "camry_2026_f33.json"
BUNDLE_SCHEMA = "toyota-diagnostics-bundle-v1"
SUPPORTED_SCHEMAS = frozenset({
  "toyota-diagnostics-registry-v1", "toyota-diagnostics-registry-v2", "toyota-diagnostics-registry-v3",
  "toyota-diagnostics-registry-v4", "toyota-diagnostics-registry-v5", "toyota-diagnostics-registry-v6",
})
DEFAULT_UDS_TIMEOUT = 0.35
DEFAULT_UDS_RESPONSE_PENDING_TIMEOUT = 2.0

DTC_STATUS_BITS: tuple[tuple[int, str], ...] = (
  (0x01, "TEST_FAILED"),
  (0x02, "TEST_FAILED_THIS_OPERATION_CYCLE"),
  (0x04, "PENDING_DTC"),
  (0x08, "CONFIRMED_DTC"),
  (0x10, "TEST_NOT_COMPLETED_SINCE_LAST_CLEAR"),
  (0x20, "TEST_FAILED_SINCE_LAST_CLEAR"),
  (0x40, "TEST_NOT_COMPLETED_THIS_OPERATION_CYCLE"),
  (0x80, "WARNING_INDICATOR_REQUESTED"),
)


class RegistryError(ValueError):
  pass


def decode_status_bits(status: int) -> list[str]:
  if not 0 <= status <= 0xFF:
    raise RegistryError(f"status byte out of range: {status:#x}")
  return [name for bit, name in DTC_STATUS_BITS if status & bit]


def parse_int(value: str | int, what: str) -> int:
  if isinstance(value, bool) or not isinstance(value, (str, int)):
    raise RegistryError(f"{what}: expected int or numeric string, got {value!r}")
  try:
    return int(value, 0) if isinstance(value, str) else value
  except ValueError as e:
    raise RegistryError(f"{what}: invalid integer: {value!r}") from e


def parse_hex_key(value: str, what: str) -> int:
  text = value.strip()
  try:
    if text.lower().startswith("0x"):
      return int(text, 16)
    if re.fullmatch(r"[0-9A-Fa-f]{4}", text):
      return int(text, 16)
    return int(text, 10)
  except ValueError as e:
    raise RegistryError(f"{what}: invalid numeric key {value!r}") from e


def parse_bytes(value: str, what: str) -> bytes:
  if not isinstance(value, str) or not value.strip():
    raise RegistryError(f"{what}: expected non-empty hex string")
  try:
    data = bytes.fromhex(value.replace(" ", ""))
  except ValueError as e:
    raise RegistryError(f"{what}: invalid hex: {value!r}") from e
  if not data:
    raise RegistryError(f"{what}: empty payload")
  return data


@dataclass(frozen=True)
class EcuSpec:
  key: str
  name: str
  address: int
  category_id: int | None = None
  functional_response: int | None = None
  sub_addr: int | None = None
  generation: int | None = None
  route_resolved: bool = True

  @property
  def endpoint(self) -> tuple[int, int | None]:
    return self.address, self.sub_addr


@dataclass(frozen=True)
class Guard:
  ecu_key: str
  did: int
  contains_ascii: str

  @property
  def contains(self) -> bytes:
    return self.contains_ascii.encode("ascii")

  @property
  def contains_hex(self) -> str:
    # Historical helper name: the exact F181 guard is an ASCII substring, not hex bytes.
    return self.contains_ascii


@dataclass(frozen=True)
class Profile:
  path: Path
  document: dict[str, Any]
  name: str
  vehicle: str
  bus: int
  fault_status_mask: int
  ecus: tuple[EcuSpec, ...]
  guard: Guard | None = None
  region: str | None = None
  vehicle_type: int | None = None
  database: ToyotaDatabase | None = None

  @property
  def uds_timeout(self) -> float:
    return DEFAULT_UDS_TIMEOUT

  @property
  def uds_response_pending_timeout(self) -> float:
    return DEFAULT_UDS_RESPONSE_PENDING_TIMEOUT

  @property
  def dtc_clear(self) -> dict[str, Any]:
    return self.document["profile"]["dtc_clear"]

  @property
  def gts_can_topology(self) -> dict[str, Any] | None:
    return self.document["profile"].get("gts_can_topology")

  @property
  def session_control(self) -> dict[str, Any] | None:
    """Raw recovered session-lifecycle metadata, or None when the registry supplies none."""
    raw = self.document["profile"].get("session_control")
    return raw if isinstance(raw, dict) else None

  @property
  def vehicle_resolution(self) -> dict[str, Any] | None:
    """Toyota vehicle/install-set/mounted-ECU/capability resolver metadata (registry v5+)."""
    raw = self.document["profile"].get("vehicle_resolution")
    return raw if isinstance(raw, dict) else None

  def category_generation_low5(self, ecu: EcuSpec | str | int) -> int | None:
    spec = ecu if isinstance(ecu, EcuSpec) else self.lookup_ecu(ecu)
    if spec.generation is not None:
      return int(spec.generation) & 0x1F
    category = self.category(spec)
    if category is None:
      return None
    meta = category.get("category")
    if not isinstance(meta, dict) or meta.get("generation") is None:
      return None
    return int(meta["generation"]) & 0x1F

  def mount_candidates(self) -> list[dict[str, Any]]:
    raw = self.vehicle_resolution
    mount = raw.get("mount") if raw is not None else None
    rows = mount.get("candidates") if isinstance(mount, dict) else None
    return rows if isinstance(rows, list) else []

  def commset(self, comm_set_id: int) -> dict[str, Any] | None:
    """Raw Toyota CommSet row; timeout units remain intentionally untranslated."""
    raw = self.document.get("commsets")
    rows = raw.get("rows") if isinstance(raw, dict) else None
    row = rows.get(str(comm_set_id)) if isinstance(rows, dict) else None
    return row if isinstance(row, dict) else None

  def session_commset(self, ecu: EcuSpec | str | int) -> tuple[int, dict[str, Any]] | None:
    """CommSet referenced by this category's recovered session frames, when v4 supplies one."""
    spec = ecu if isinstance(ecu, EcuSpec) else self.lookup_ecu(ecu)
    raw = self.session_control
    per_category = raw.get("per_category") if raw is not None else None
    category = per_category.get(str(spec.category_id)) if isinstance(per_category, dict) else None
    if not isinstance(category, dict):
      return None
    ids = {
      int(frame["comm_set"])
      for key in ("default_session", "extended_session", "keepalive")
      if isinstance((frame := category.get(key)), dict) and frame.get("comm_set") is not None
    }
    if not ids:
      return None
    if len(ids) != 1:
      raise RegistryError(f"session_control category {spec.category_id}: expected one shared CommSet, got {sorted(ids)}")
    comm_set_id = next(iter(ids))
    row = self.commset(comm_set_id)
    if row is None:
      raise RegistryError(f"session_control category {spec.category_id}: CommSet {comm_set_id} is not present")
    return comm_set_id, row

  def observed_identity(self, ecu: EcuSpec | str | int) -> dict[str, Any] | None:
    spec = ecu if isinstance(ecu, EcuSpec) else self.lookup_ecu(ecu)
    rows = self.document.get("profile", {}).get("ecus", [])
    raw = next((row for row in rows if row.get("key") == spec.key), None)
    identity = raw.get("observed_identity") if isinstance(raw, dict) else None
    return identity if isinstance(identity, dict) else None

  @property
  def legislated_responders(self) -> frozenset[int]:
    clear = self.document.get("profile", {}).get("dtc_clear")
    functional = clear.get("functional_obd") if isinstance(clear, dict) else None
    expected = functional.get("expected_responders") if isinstance(functional, dict) else None
    if isinstance(expected, list):
      return frozenset(int(value) for value in expected)
    return frozenset(ecu.functional_response for ecu in self.ecus if ecu.functional_response)

  @property
  def mode04_request(self) -> bytes:
    clear = self.document.get("profile", {}).get("dtc_clear")
    functional = clear.get("functional_obd") if isinstance(clear, dict) else None
    value = functional.get("mode04_request") if isinstance(functional, dict) else None
    return bytes.fromhex(str(value or "0104000000000000"))

  def scanned_ecus(self) -> tuple[EcuSpec, ...]:
    """Resolved logical ECU endpoints for the selected vehicle/profile."""
    return self.ecus

  def lookup_ecu(self, ref: str | int) -> EcuSpec:
    if isinstance(ref, int):
      matches = [ecu for ecu in self.ecus if ecu.route_resolved and ecu.address == ref]
    else:
      text = ref.strip()
      try:
        address = int(text, 0) if text.lower().startswith("0x") else None
      except ValueError:
        address = None
      if address is not None:
        matches = [ecu for ecu in self.ecus if ecu.route_resolved and ecu.address == address]
      else:
        needle = text.casefold()
        matches = [ecu for ecu in self.ecus if needle in {ecu.key.casefold(), ecu.name.casefold()}]
        if not matches:
          matches = [ecu for ecu in self.ecus if ecu.category_id is not None and needle == self.category(ecu)["category"]["name"].casefold()]
    if len(matches) == 1:
      return matches[0]
    if not matches:
      suggestions = self.suggest_ecus(str(ref))
      hint = ""
      if suggestions:
        hint = "; did you mean " + ", ".join(f"{ecu.key} ({ecu.name})" for ecu in suggestions) + "?"
      raise RegistryError(f"no ECU matches {ref!r}{hint}")
    raise RegistryError(f"ambiguous ECU {ref!r}: {', '.join(ecu.key for ecu in matches)}")

  def name_for(self, address: int) -> str:
    try:
      return self.lookup_ecu(address).name
    except RegistryError:
      return f"ECU {address:#05x}"

  def category(self, ecu: EcuSpec | str | int) -> dict[str, Any] | None:
    spec = ecu if isinstance(ecu, EcuSpec) else self.lookup_ecu(ecu)
    if spec.category_id is None:
      return None
    return self.document["catalogs"].get(str(spec.category_id))

  def dids(self, ecu: EcuSpec | str | int) -> dict[str, list[dict[str, Any]]]:
    category = self.category(ecu)
    return {} if category is None else category["dids"]

  def dtcs(self, ecu: EcuSpec | str | int) -> dict[str, list[dict[str, Any]]]:
    category = self.category(ecu)
    return {} if category is None else category["dtcs"]

  def active_tests(self, ecu: EcuSpec | str | int) -> list[dict[str, Any]]:
    category = self.category(ecu)
    return [] if category is None else category.get("active_tests", [])

  def functions(self, ecu: EcuSpec | str | int) -> list[dict[str, Any]]:
    category = self.category(ecu)
    return [] if category is None else category.get("functions", [])

  def roles(self, ecu: EcuSpec | str | int) -> list[dict[str, Any]]:
    category = self.category(ecu)
    if category is None:
      return []
    rows = category.get("roles")
    if isinstance(rows, list):
      return rows
    # Registry v4 names the recovered role→DLL surface `plugins`.
    plugins = category.get("plugins")
    return plugins if isinstance(plugins, list) else []

  @property
  def utility_metadata(self) -> dict[str, Any] | None:
    raw = self.document.get("utilities")
    return raw if isinstance(raw, dict) else None

  def utility_bindings(self) -> list[dict[str, Any]]:
    raw = self.utility_metadata
    rows = raw.get("bindings") if raw is not None else None
    return rows if isinstance(rows, list) else []

  def suggest_ecus(self, ref: str, limit: int = 5) -> list[EcuSpec]:
    import difflib
    needle = ref.casefold()
    keyed: dict[str, EcuSpec] = {}
    for ecu in self.ecus:
      labels = [ecu.key, ecu.name]
      if ecu.route_resolved:
        labels.append(f"0x{ecu.address:X}")
      for label in labels:
        keyed[label.casefold()] = ecu
      category = self.category(ecu)
      if category is not None:
        meta = category.get("category", {})
        for label in (meta.get("name"), meta.get("database")):
          if label:
            keyed[str(label).casefold()] = ecu
    matches = difflib.get_close_matches(needle, list(keyed), n=limit, cutoff=0.35)
    out: list[EcuSpec] = []
    for match in matches:
      ecu = keyed[match]
      if ecu not in out:
        out.append(ecu)
    return out

  def utilities(self, ecu: EcuSpec | str | int) -> list[dict[str, Any]]:
    """Concrete per-ECU utility rows, when a registry has recovered them.

    Registry v4 currently carries generic utility-family metadata at top level,
    but deliberately contains no concrete per-ECU utility execution rows.
    """
    category = self.category(ecu)
    rows = category.get("utilities") if category is not None else None
    return rows if isinstance(rows, list) else []

  def lookup_utility(self, ecu: EcuSpec | str | int, query: str, kind: str | None = None) -> dict[str, Any]:
    rows = [row for row in self.utilities(ecu) if kind is None or row.get("kind") == kind]
    return _lookup_catalog_rows(rows, query, "utility")

  def lookup_utility_family(self, query: str) -> dict[str, Any]:
    rows = self.utility_bindings()
    try:
      role = parse_hex_key(query, "utility role")
    except RegistryError:
      role = None
    if role is not None:
      matches = [row for row in rows if row.get("role") == role]
    else:
      needle = query.casefold()
      matches = [
        row for row in rows
        if needle in str(row.get("semantic_kind") or "").casefold()
        or needle in str(row.get("dll") or "").casefold()
      ]
    matches = _dedupe_rows(matches)
    if len(matches) == 1:
      return matches[0]
    if not matches:
      raise RegistryError(f"no utility family matches {query!r}")
    raise RegistryError(f"ambiguous utility family {query!r}; use an exact semantic kind or numeric role")

  def lookup_active_test(self, ecu: EcuSpec | str | int, query: str, kind: str | None = None) -> dict[str, Any]:
    tests = [row for row in self.active_tests(ecu) if kind is None or row.get("kind") == kind]
    return _lookup_catalog_rows(tests, query, "Active Test")

  def resolve_did(self, ecu: EcuSpec | str | int, query: str) -> tuple[int, list[dict[str, Any]]]:
    dids = self.dids(ecu)
    try:
      did = parse_hex_key(query, "DID")
    except RegistryError:
      did = None
    if did is not None:
      return did, dids.get(f"0x{did:04X}", [])

    needle = query.casefold()
    exact: dict[int, list[dict[str, Any]]] = {}
    fuzzy: dict[int, list[dict[str, Any]]] = {}
    for key, rows in dids.items():
      number = int(key, 16)
      for row in rows:
        name = str(row.get("name") or "")
        if name.casefold() == needle:
          exact.setdefault(number, rows)
        elif needle in name.casefold():
          fuzzy.setdefault(number, rows)
    matches = exact or fuzzy
    if len(matches) == 1:
      return next(iter(matches.items()))
    if not matches:
      raise RegistryError(f"no DID matches {query!r}")
    raise RegistryError(f"DID name {query!r} maps to multiple DIDs: {', '.join(f'0x{x:04X}' for x in matches)}")

  def describe_dtc(self, ecu: EcuSpec | str | int, code: str) -> list[dict[str, Any]]:
    needle = re.sub(r"[^0-9A-Za-z]", "", code).casefold()
    out = []
    for rows in self.dtcs(ecu).values():
      for row in rows:
        if re.sub(r"[^0-9A-Za-z]", "", str(row.get("code") or "")).casefold() == needle:
          out.append(row)
    return out


ECU_KEY_ALIASES = {
  372: "engine",
  395: "motor_generator",
  397: "hybrid",
  398: "hv_battery",
  405: "eps",
  435: "brake",
  450: "air_conditioner",
  498: "frc",
}


def _category_key(category_id: int, row: dict[str, Any]) -> str:
  if category_id in ECU_KEY_ALIASES:
    return ECU_KEY_ALIASES[category_id]
  source = str(row.get("short_name") or Path(str(row.get("database") or "")).stem or f"category_{category_id}")
  source = re.sub(r"_P[456].*$", "", source, flags=re.IGNORECASE)
  key = re.sub(r"[^0-9A-Za-z]+", "_", source).strip("_").casefold()
  return key or f"category_{category_id}"


def _legislated_response_address(route: dict[str, Any]) -> int | None:
  """Translate Toyota class-0x10D's legislated physical request to its 11-bit OBD response."""
  request = int(route.get("legislated_request_address") or 0)
  if request == 0:
    return None
  if not 0x7E0 <= request <= 0x7E7:
    raise RegistryError(f"unsupported Toyota legislated request address 0x{request:X}; expected standard 0x7E0..0x7E7")
  return request + 8


class LazyCatalogs(Mapping[str, dict[str, Any]]):
  """Lazy catalog mapping backed by compressed members in the universal ZIP bundle."""

  def __init__(self, path: Path, category_index: dict[str, Any]) -> None:
    self.path = path
    self.category_index = category_index
    self._keys = tuple(sorted(
      (key for key, row in category_index.items() if isinstance(row, dict) and row.get("catalog_member")),
      key=int,
    ))
    self._cache: dict[str, dict[str, Any]] = {}

  def __iter__(self) -> Iterator[str]:
    return iter(self._keys)

  def __len__(self) -> int:
    return len(self._keys)

  def __getitem__(self, key: str) -> dict[str, Any]:
    text = str(key)
    if text in self._cache:
      return self._cache[text]
    row = self.category_index.get(text)
    if not isinstance(row, dict) or not row.get("catalog_member"):
      raise KeyError(text)
    try:
      with zipfile.ZipFile(self.path) as archive:
        payload = json.loads(archive.read(str(row["catalog_member"])))
    except (FileNotFoundError, KeyError, zipfile.BadZipFile, json.JSONDecodeError) as e:
      raise RegistryError(f"cannot load Toyota catalog {text} from {self.path}: {e}") from e
    if not isinstance(payload, dict):
      raise RegistryError(f"Toyota catalog {text} is not an object")
    self._cache[text] = payload
    return payload


@dataclass(frozen=True)
class ToyotaDatabase:
  path: Path
  index: dict[str, Any]

  @classmethod
  def load(cls, path: str | Path = DEFAULT_REGISTRY) -> ToyotaDatabase:
    bundle = Path(path)
    try:
      with zipfile.ZipFile(bundle) as archive:
        index = json.loads(archive.read("index.json"))
    except FileNotFoundError as e:
      raise RegistryError(f"Toyota diagnostic bundle not found: {bundle}") from e
    except (KeyError, zipfile.BadZipFile, json.JSONDecodeError) as e:
      raise RegistryError(f"invalid Toyota diagnostic bundle {bundle}: {e}") from e
    if index.get("schema") != BUNDLE_SCHEMA:
      raise RegistryError(f"unsupported Toyota diagnostic bundle schema {index.get('schema')!r}")
    if not isinstance(index.get("regions"), dict) or not index["regions"]:
      raise RegistryError("Toyota diagnostic bundle contains no regional indexes")
    return cls(bundle, index)

  @property
  def default_region(self) -> str:
    return str(self.index.get("default_region") or "NA")

  def region_index(self, region: str | None = None) -> dict[str, Any]:
    key = (region or self.default_region).upper()
    row = self.index["regions"].get(key)
    if not isinstance(row, dict):
      raise RegistryError(f"unknown Toyota GTS region {key!r}; available: {', '.join(sorted(self.index['regions']))}")
    return row

  def vehicle_rows(self, region: str | None = None) -> list[dict[str, Any]]:
    raw = self.region_index(region).get("vehicles")
    if not isinstance(raw, dict):
      return []
    return sorted((dict(row) for row in raw.values() if isinstance(row, dict)), key=lambda row: (str(row.get("name") or ""), int(row["vehicle_type"])))

  def resolve_vehicle(self, region: str, ref: str | int) -> dict[str, Any]:
    rows = self.vehicle_rows(region)
    numeric = None
    if isinstance(ref, int):
      numeric = ref
    else:
      try:
        numeric = int(ref, 0)
      except ValueError:
        numeric = None
    if numeric is not None:
      matches = [row for row in rows if int(row["vehicle_type"]) == numeric]
    else:
      needle = str(ref).casefold()
      exact = [row for row in rows if str(row.get("name") or "").casefold() == needle]
      matches = exact or [row for row in rows if needle in str(row.get("name") or "").casefold()]
    if len(matches) == 1:
      return matches[0]
    if not matches:
      raise RegistryError(f"no Toyota {region} vehicle matches {ref!r}")
    summary = ", ".join(f"{row['vehicle_type']} {row.get('name') or '(unnamed)'}" for row in matches[:12])
    raise RegistryError(f"ambiguous Toyota vehicle {ref!r}: {summary}")

  @staticmethod
  def _vin_row_matches(row: dict[str, Any], vin: str) -> bool:
    if len(vin) != 17:
      return False
    try:
      flags = int(row["flags"])
      prefix = bytes.fromhex(str(row["vin_prefix_hex"]))
    except (KeyError, TypeError, ValueError):
      return False
    if len(prefix) != 11:
      return False
    vin11 = vin[:11].encode("ascii", errors="ignore")
    return len(vin11) == 11 and all((flags & (1 << index)) or prefix[index] == vin11[index] for index in range(11))

  def vin_source_keys(self, region: str, rx_address: int | None) -> set[tuple[int, int]]:
    if rx_address is None:
      return set()
    routes = self.region_index(region).get("routes")
    if not isinstance(routes, dict):
      return set()
    out: set[tuple[int, int]] = set()
    for key, row in routes.items():
      if not isinstance(row, dict) or _legislated_response_address(row) != rx_address:
        continue
      try:
        category_text, phase_text = str(key).split(":", 1)
        out.add((int(category_text), int(phase_text)))
      except ValueError:
        continue
    return out

  def resolve_vin(self, region: str, vin: str, *, rx_address: int | None = None) -> list[dict[str, Any]]:
    index = self.region_index(region)
    decision = index.get("vin_decision")
    rows = decision.get("rows") if isinstance(decision, dict) else None
    if not isinstance(rows, list):
      raise RegistryError(f"Toyota {region} index has no VIN decision rows")
    source_keys = self.vin_source_keys(region, rx_address)
    candidates = [
      row for row in rows
      if self._vin_row_matches(row, vin)
      and (not source_keys or (int(row.get("category_id", -1)), int(row.get("phase_type", -1))) in source_keys)
    ]
    if not candidates and source_keys:
      candidates = [row for row in rows if self._vin_row_matches(row, vin)]
    by_type: dict[int, list[dict[str, Any]]] = {}
    for row in candidates:
      by_type.setdefault(int(row["vehicle_type"]), []).append(row)
    vehicles = index.get("vehicles") if isinstance(index.get("vehicles"), dict) else {}
    out = []
    for vehicle_type, decision_rows in sorted(by_type.items()):
      vehicle = vehicles.get(str(vehicle_type))
      if not isinstance(vehicle, dict):
        continue
      out.append({
        **dict(vehicle),
        "region": region,
        "decision_rows": decision_rows,
        "source_keys": sorted([list(key) for key in source_keys]),
      })
    return out

  def _catalogs(self, region: str) -> LazyCatalogs:
    categories = self.region_index(region).get("categories")
    if not isinstance(categories, dict):
      raise RegistryError(f"Toyota {region} index has no category catalog index")
    return LazyCatalogs(self.path, categories)

  def _candidate_rows(self, region: str, vehicle: dict[str, Any]) -> list[dict[str, Any]]:
    index = self.region_index(region)
    install_sets = index.get("install_sets") if isinstance(index.get("install_sets"), dict) else {}
    categories = index.get("categories") if isinstance(index.get("categories"), dict) else {}
    routes = index.get("routes") if isinstance(index.get("routes"), dict) else {}
    out: list[dict[str, Any]] = []
    seen: set[tuple[int, int, str | None]] = set()
    for install_set_id in vehicle.get("install_set_ids") or []:
      for raw in install_sets.get(str(install_set_id), []):
        if not isinstance(raw, dict):
          continue
        category_id = int(raw["category_id"])
        phase_type = int(raw["connection_phase_type"])
        route_key = raw.get("route_key")
        identity = (category_id, phase_type, str(route_key) if route_key is not None else None)
        if identity in seen:
          continue
        seen.add(identity)
        category = categories.get(str(category_id)) if isinstance(categories, dict) else None
        row = dict(raw)
        row["install_set_id"] = int(install_set_id)
        if isinstance(category, dict):
          row.update({
            "generation": category.get("generation"),
            "database": category.get("database"),
            "short_name": category.get("short_name"),
            "name": category.get("name"),
            "current_p5_supported": bool(category.get("current_p5_supported")),
          })
        route = routes.get(str(route_key)) if route_key is not None else None
        if isinstance(route, dict):
          row["transport_route"] = route
        out.append(row)
    return sorted(out, key=lambda row: (int(row["category_id"]), int(row["connection_phase_type"])))

  @staticmethod
  def _ecu_specs(candidates: list[dict[str, Any]], *, supported_only: bool = True) -> tuple[EcuSpec, ...]:
    rows = []
    used_keys: set[str] = set()
    used_endpoints: set[tuple[int, int | None, int]] = set()
    for row in candidates:
      if supported_only and not row.get("current_p5_supported"):
        continue
      route = row.get("transport_route")
      if not isinstance(route, dict):
        continue
      category_id = int(row["category_id"])
      address = int(route["request_address"])
      sub_addr = int(route.get("address_extension") or 0) or None
      endpoint_key = (address, sub_addr, category_id)
      if endpoint_key in used_endpoints:
        continue
      used_endpoints.add(endpoint_key)
      key = _category_key(category_id, row)
      if key in used_keys:
        key = f"{key}_{category_id}"
      used_keys.add(key)
      rows.append(EcuSpec(
        key=key,
        name=str(row.get("name") or row.get("short_name") or f"Category {category_id}"),
        address=address,
        category_id=category_id,
        functional_response=_legislated_response_address(route),
        sub_addr=sub_addr,
        generation=int(row["generation"]) if row.get("generation") is not None else None,
      ))
    return tuple(rows)

  def profile(self, region: str | None = None, vehicle: str | int | None = None, *, bus: int | None = None) -> Profile:
    region_key = (region or self.default_region).upper()
    index = self.region_index(region_key)
    catalogs = self._catalogs(region_key)
    selected = self.resolve_vehicle(region_key, vehicle) if vehicle is not None else None
    if selected is None:
      categories = index.get("categories") if isinstance(index.get("categories"), dict) else {}
      ecus = tuple(
        EcuSpec(
          key=_category_key(int(category_id), category),
          name=str(category.get("name") or category.get("short_name") or f"Category {category_id}"),
          address=0,
          category_id=int(category_id),
          generation=int(category["generation"]) if category.get("generation") is not None else None,
          route_resolved=False,
        )
        for category_id in index.get("supported_p5_category_ids") or []
        if isinstance((category := categories.get(str(category_id))), dict)
      )
      profile_name = f"toyota-current-{region_key.casefold()}"
      vehicle_name = f"Toyota current-P5 catalog ({region_key}; no vehicle selected)"
      vehicle_resolution = None
      vehicle_type = None
      topology = None
    else:
      candidates = self._candidate_rows(region_key, selected)
      ecus = self._ecu_specs(candidates)
      profile_name = f"toyota-{region_key.casefold()}-{int(selected['vehicle_type'])}"
      vehicle_name = f"Toyota {selected.get('name') or selected['vehicle_type']}"
      vehicle_type = int(selected["vehicle_type"])
      vehicle_resolution = {
        "generation": "current-gtsplus-universal-resolver-v1",
        "vehicle_type": vehicle_type,
        "vehicle_name": selected.get("name") or "",
        "install_set_ids": list(selected.get("install_set_ids") or []),
        "mount": {
          "algorithm": "GetMountEcuListNoCnfm/CEcuConnectCheck::CommConnectionNoBuffer",
          "candidate_count": len(candidates),
          "candidates": candidates,
        },
        "p5_support": self.index.get("p5_support"),
      }
      topology_rows = index.get("can_topology", {}).get(str(vehicle_type), []) if isinstance(index.get("can_topology"), dict) else []
      topology = topology_rows[0] if len(topology_rows) == 1 else ({"rows": topology_rows} if topology_rows else None)

    profile_rows = [{
      "key": ecu.key,
      "name": ecu.name,
      "address": ecu.address,
      "sub_addr": ecu.sub_addr,
      "category_id": ecu.category_id,
      "functional_response": ecu.functional_response,
      "generation": ecu.generation,
      "route_resolved": ecu.route_resolved,
    } for ecu in ecus]
    document: dict[str, Any] = {
      "schema": BUNDLE_SCHEMA,
      "profile": {
        "profile": profile_name,
        "vehicle": vehicle_name,
        "panda_bus": int(self.index.get("default_panda_bus", 0) if bus is None else bus),
        "fault_status_mask": int(self.index.get("fault_status_mask", 0xAF)),
        "ecus": profile_rows,
        "session_control": index.get("session_control"),
        "vehicle_resolution": vehicle_resolution,
        "gts_can_topology": topology,
        "dtc_clear": {
          "functional_obd": {
            "request_id": 0x7DF,
            "mode04_request": str(self.index.get("mode04_request") or "0104000000000000"),
            "expected_responders": sorted(ecu.functional_response for ecu in ecus if ecu.functional_response),
          },
        },
      },
      "catalogs": catalogs,
      "commsets": {"rows": index.get("commsets") or {}},
      "utilities": index.get("utilities"),
      "decoders": self.index.get("decoders") or {},
      "function_names": self.index.get("function_names"),
      "boundary": self.index.get("boundary"),
    }
    return Profile(
      path=self.path,
      document=document,
      name=profile_name,
      vehicle=vehicle_name,
      bus=int(document["profile"]["panda_bus"]),
      fault_status_mask=int(document["profile"]["fault_status_mask"]),
      ecus=ecus,
      guard=None,
      region=region_key,
      vehicle_type=vehicle_type,
      database=self,
    )


def _dedupe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
  """Preserve order while collapsing byte-for-byte-equivalent catalog rows."""
  out: list[dict[str, Any]] = []
  for row in rows:
    if row not in out:
      out.append(row)
  return out


def _lookup_catalog_rows(rows: list[dict[str, Any]], query: str, what: str) -> dict[str, Any]:
  rows = _dedupe_rows(rows)
  try:
    item = parse_hex_key(query, what)
  except RegistryError:
    item = None
  if item is not None:
    matches = [row for row in rows if row.get("id") == item]
  else:
    needle = query.casefold()
    exact = [row for row in rows if str(row.get("name") or "").casefold() == needle]
    matches = exact or [row for row in rows if needle in str(row.get("name") or "").casefold()]
  if len(matches) == 1:
    return matches[0]
  if not matches:
    raise RegistryError(f"no {what} matches {query!r}")
  raise RegistryError(f"ambiguous {what} {query!r}; specify --kind or numeric ID")


@dataclass(frozen=True)
class CommTimeouts:
  """CommSet-style UDS timing in seconds, mirroring the UdsClient constructor units."""
  uds_timeout: float
  response_pending_timeout: float


_COMMSET_KEYS = frozenset({"uds_timeout_s", "response_pending_timeout_s"})


def parse_seconds(value: Any, what: str) -> float:
  if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)) or value <= 0:
    raise RegistryError(f"{what}: expected a positive finite number of seconds, got {value!r}")
  return float(value)


def commset_timeouts(profile: Profile, row: dict[str, Any] | None = None) -> CommTimeouts:
  """Resolve CommSet timeouts: operation row overrides profile session metadata overrides runtime defaults."""
  sources: list[tuple[str, Any]] = []
  raw = profile.session_control
  if raw is not None and raw.get("commset") is not None:
    sources.append(("profile session_control.commset", raw["commset"]))
  if row is not None and row.get("commset") is not None:
    sources.append(("operation commset", row["commset"]))
  values: dict[str, float] = {
    "uds_timeout_s": profile.uds_timeout,
    "response_pending_timeout_s": profile.uds_response_pending_timeout,
  }
  for what, commset in sources:
    if not isinstance(commset, dict):
      raise RegistryError(f"{what}: expected an object")
    unknown = sorted(set(commset) - _COMMSET_KEYS)
    if unknown:
      raise RegistryError(f"{what}: unsupported commset keys: {', '.join(unknown)}")
    for key in sorted(_COMMSET_KEYS):
      if key in commset:
        values[key] = parse_seconds(commset[key], f"{what}.{key}")
  return CommTimeouts(uds_timeout=values["uds_timeout_s"], response_pending_timeout=values["response_pending_timeout_s"])


def _load_ecus(profile: dict[str, Any]) -> tuple[EcuSpec, ...]:
  rows = profile.get("ecus")
  if not isinstance(rows, list) or not rows:
    raise RegistryError("profile.ecus must be a non-empty list")
  ecus = tuple(EcuSpec(
    key=str(row["key"]), name=str(row["name"]), address=int(row["address"]),
    category_id=int(row["category_id"]) if row.get("category_id") is not None else None,
    functional_response=int(row["functional_response"]) if row.get("functional_response") is not None else None,
    sub_addr=int(row["sub_addr"]) if row.get("sub_addr") is not None else None,
    generation=int(row["generation"]) if row.get("generation") is not None else None,
    route_resolved=bool(row.get("route_resolved", True)),
  ) for row in rows)
  if len({ecu.key for ecu in ecus}) != len(ecus):
    raise RegistryError("profile.ecus contains duplicate keys")
  if len({(ecu.address, ecu.sub_addr, ecu.category_id) for ecu in ecus}) != len(ecus):
    raise RegistryError("profile.ecus contains duplicate logical endpoints")
  return ecus


def available_registries(directory: Path | None = None) -> list[Path]:
  root = DEFAULT_REGISTRY.parent if directory is None else Path(directory)
  return sorted(path for path in root.iterdir() if path.is_file() and path.suffix.casefold() in {".json", ".zip"})


def _resolve_registry_path(path: str | Path) -> Path:
  candidate = Path(path)
  if candidate.exists():
    return candidate
  text = str(path)
  if "/" not in text and "\\" not in text:
    for item in available_registries():
      try:
        if item.suffix.casefold() == ".zip":
          with zipfile.ZipFile(item) as archive:
            document = json.loads(archive.read("index.json"))
          if str(document.get("profile")) == text:
            return item
          continue
        document = json.loads(item.read_text())
      except (OSError, KeyError, zipfile.BadZipFile, json.JSONDecodeError):
        continue
      raw = document.get("profile")
      if isinstance(raw, dict) and str(raw.get("profile")) == text:
        return item
  return candidate


def load_database(path: str | Path = DEFAULT_REGISTRY) -> ToyotaDatabase:
  resolved = _resolve_registry_path(path)
  if resolved.suffix.casefold() != ".zip":
    raise RegistryError(f"registry {resolved} is a legacy single-vehicle JSON, not a universal Toyota bundle")
  return ToyotaDatabase.load(resolved)


def load_registry(
  path: str | Path = DEFAULT_REGISTRY,
  *,
  region: str | None = None,
  vehicle: str | int | None = None,
  bus: int | None = None,
) -> Profile:
  path = _resolve_registry_path(path)
  if path.suffix.casefold() == ".zip":
    return ToyotaDatabase.load(path).profile(region, vehicle, bus=bus)
  try:
    document = json.loads(path.read_text())
  except FileNotFoundError as e:
    raise RegistryError(f"registry file not found: {path}") from e
  except json.JSONDecodeError as e:
    raise RegistryError(f"registry is not valid JSON: {path}: {e}") from e
  if document.get("schema") not in SUPPORTED_SCHEMAS:
    raise RegistryError(f"unsupported registry schema {document.get('schema')!r}")
  raw = document.get("profile")
  if not isinstance(raw, dict):
    raise RegistryError("missing profile object")
  ecus = _load_ecus(raw)
  categories = document.get("catalogs")
  if not isinstance(categories, dict):
    raise RegistryError("missing catalogs object")
  for ecu in ecus:
    if ecu.category_id is not None and str(ecu.category_id) not in categories:
      raise RegistryError(f"ECU {ecu.key} references missing category {ecu.category_id}")
  guard_row = raw.get("identity_guard")
  guard = None
  if isinstance(guard_row, dict):
    guard = Guard(str(guard_row["ecu"]), int(guard_row["did"]), str(guard_row["contains_ascii"]))
  profile = Profile(
    path=path,
    document=document,
    name=str(raw["profile"]),
    vehicle=str(raw["vehicle"]),
    bus=int(raw["panda_bus"] if bus is None else bus),
    fault_status_mask=int(raw["fault_status_mask"]),
    ecus=ecus,
    guard=guard,
  )
  if guard is not None:
    profile.lookup_ecu(guard.ecu_key)
  return profile
