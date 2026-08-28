"""High-level read-only Toyota vehicle inventory snapshots."""
from __future__ import annotations

from typing import Any

from tools.toyota_diag import dtc
from tools.toyota_diag.registry import Profile, decode_status_bits

IDENTITY_DIDS = (0xF181, 0xF18C, 0x0105)


def _safe_read(client, did: int) -> bytes | None:
  try:
    return bytes(client.read_data_by_identifier(did))
  except Exception:
    return None


def _ascii(data: bytes | None) -> str | None:
  if not data:
    return None
  text = "".join(chr(value) if 32 <= value < 127 else "" for value in data).strip("\x00 \t\r\n")
  return text or None


def build(profile: Profile, client_factory, transport_state: dict[str, Any] | None = None, *, show_all_dtcs: bool = False) -> dict[str, Any]:
  responding, faults = dtc.scan(
    client_factory,
    [(ecu.address, ecu.name) for ecu in profile.scanned_ecus()],
    profile.fault_status_mask,
    show_all=show_all_dtcs,
    echo=lambda _: None,
  )
  ecus = []
  for address, records in responding.items():
    try:
      spec = profile.lookup_ecu(address)
      key = spec.key
      name = spec.name
      category_id = spec.category_id
    except Exception:
      spec = None
      key = None
      name = profile.name_for(address)
      category_id = None
    client = client_factory(address)
    identity = {}
    for did in IDENTITY_DIDS:
      raw = _safe_read(client, did)
      if raw is not None:
        identity[f"0x{did:04X}"] = {"data_hex": raw.hex(), "ascii": _ascii(raw)}
    dtcs = []
    for code, status in records:
      dtcs.append({
        "code": code,
        "status": status,
        "status_bits": decode_status_bits(status),
        "fault_status": bool(status & profile.fault_status_mask),
        "descriptions": profile.describe_dtc(spec or address, code) if spec is not None else [],
      })
    ecus.append({
      "key": key,
      "name": name,
      "address": address,
      "category_id": category_id,
      "identity": identity,
      "dtcs": dtcs,
      "fault_count": sum(1 for row in dtcs if row["fault_status"]),
    })
  return {
    "profile": profile.name,
    "vehicle": profile.vehicle,
    "panda_bus": profile.bus,
    "transport": transport_state,
    "responding_ecus": len(ecus),
    "fault_status_records": len(faults),
    "ecus": ecus,
  }


def render(document: dict[str, Any]) -> str:
  transport = document.get("transport") or {}
  lines = [document["vehicle"], ""]
  if transport:
    lines.append(f"Transport: {transport.get('mode', '?')} ({'ready' if transport.get('ready') else 'not ready'})")
  lines.append(f"Profile:   {document['profile']}  Panda bus={document['panda_bus']}")
  lines.append(f"ECUs:      {document['responding_ecus']} responding")
  lines.append(f"DTCs:      {document['fault_status_records']} fault-status record(s)")
  lines.append("")
  for row in document["ecus"]:
    mark = "!" if row["fault_count"] else "✓"
    ident = row.get("identity", {})
    f181 = (ident.get("0xF181") or {}).get("ascii")
    suffix = f"  {f181}" if f181 else ""
    key = row.get("key") or "?"
    lines.append(f"{mark} {row['name']:<30} {row['address']:#05x}  {key:<18}{suffix}")
    for fault in row["dtcs"]:
      if not fault["fault_status"]:
        continue
      desc = fault["descriptions"][0] if fault["descriptions"] else {}
      label = desc.get("description") or fault["code"]
      failure = desc.get("failure")
      extra = f" — {failure}" if failure else ""
      lines.append(f"    {fault['code']} {fault['status']:#04x}  {label}{extra}")
  return "\n".join(lines)
