"""Unified Comma-side Toyota diagnostic CLI."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from tools.toyota_diag import active_test, decode, dtc, registry
from tools.toyota_diag.registry import Profile

READ_ONLY_UDS_SERVICES = frozenset({0x19, 0x22, 0x23, 0x24, 0x3E})
READ_ONLY_OBD_MODES = frozenset({0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x09, 0x0A})


def _cli_int(value: str, what: str) -> int:
  try:
    return registry.parse_int(value, what)
  except registry.RegistryError as e:
    raise SystemExit(str(e)) from e


def _profile(args) -> Profile:
  try:
    return registry.load_registry(args.registry)
  except registry.RegistryError as e:
    raise SystemExit(f"invalid registry {args.registry}: {e}") from e


def _live_transport():
  from tools.toyota_diag import transport
  return transport


def _guard_specs(profile: Profile):
  ecu = profile.lookup_ecu(profile.guard.ecu_key)
  return [(ecu.address, ecu.name, profile.guard)]


def _guard(profile: Profile, client_factory) -> None:
  dtc.verify_vehicle_identity(client_factory, _guard_specs(profile))


def _format_signal(row: dict[str, Any]) -> str:
  bits = f"bits {row.get('bit_start')}..{row.get('bit_end')}"
  scale = f"scale {row.get('mul')}/{row.get('div')} offset {row.get('offset')}"
  unit = f" {row['unit']}" if row.get("unit") else ""
  signed = " signed" if row.get("signed") else ""
  patterns = row.get("patterns") or {}
  pattern_text = f" patterns={patterns}" if patterns else ""
  return f"{row.get('name') or '(unnamed)'} [{bits}; {scale}{unit}{signed}]{pattern_text}"


def _filter_rows(rows: list[tuple[int, dict[str, Any]]], query: str | None) -> list[tuple[int, dict[str, Any]]]:
  if not query:
    return rows
  needle = query.casefold()
  return [(key, row) for key, row in rows if needle in f"0x{key:04x} {row}".casefold()]


# Offline --------------------------------------------------------------------
def cmd_ecu_list(args, profile: Profile) -> int:
  print(f"{profile.vehicle}  profile={profile.name}  Panda bus={profile.bus}")
  for ecu in profile.ecus:
    category = f"cat {ecu.category_id}" if ecu.category_id is not None else "cat ?"
    obd = f" OBD-rx={ecu.functional_response:#05x}" if ecu.functional_response is not None else ""
    print(f"{ecu.address:#05x}  {ecu.key:<18} {ecu.name:<28} {category}{obd}")
  return 0


def cmd_ecu_info(args, profile: Profile) -> int:
  try:
    ecu = profile.lookup_ecu(args.ecu)
  except registry.RegistryError as e:
    raise SystemExit(str(e)) from e
  print(f"key:       {ecu.key}")
  print(f"name:      {ecu.name}")
  print(f"address:   {ecu.address:#05x}")
  print(f"Panda bus: {profile.bus}")
  print(f"category:  {ecu.category_id if ecu.category_id is not None else '(unresolved)'}")
  if ecu.functional_response is not None:
    print(f"OBD rx:    {ecu.functional_response:#05x}")
  category = profile.category(ecu)
  if category is not None:
    meta = category["category"]
    print(f"GTS DB:    {meta['database']} ({meta['name']})")
    print(f"DIDs:      {len(category['dids'])}")
    print(f"DTCs:      {len(category['dtcs'])}")
    print(f"Active Tests: {len(category['active_tests'])} candidate(s), plan-only")
  if ecu.key == profile.guard.ecu_key:
    print(f"mutation guard: DID 0x{profile.guard.did:04X} contains {profile.guard.contains_ascii}")
  return 0


def cmd_did_list(args, profile: Profile) -> int:
  try:
    ecu = profile.lookup_ecu(args.ecu)
  except registry.RegistryError as e:
    raise SystemExit(str(e)) from e
  rows = [(int(key, 16), row) for key, signals in profile.dids(ecu).items() for row in signals]
  rows = _filter_rows(rows, args.query)
  for did, row in rows[:args.limit]:
    print(f"0x{did:04X}  {_format_signal(row)}")
  if len(rows) > args.limit:
    print(f"... {len(rows) - args.limit} more; raise --limit")
  return 0


def cmd_dtc_catalog(args, profile: Profile) -> int:
  try:
    ecu = profile.lookup_ecu(args.ecu)
  except registry.RegistryError as e:
    raise SystemExit(str(e)) from e
  rows = [(int(key, 16), row) for key, items in profile.dtcs(ecu).items() for row in items]
  rows = _filter_rows(rows, args.query)
  for raw, row in rows[:args.limit]:
    failure = f" — {row['failure']}" if row.get("failure") else ""
    print(f"{row.get('code') or f'0x{raw:06X}'}  {row.get('description') or ''}{failure}")
  if len(rows) > args.limit:
    print(f"... {len(rows) - args.limit} more; raise --limit")
  return 0


def cmd_dtc_decode(args, profile: Profile) -> int:
  status = _cli_int(args.status, "status")
  if not 0 <= status <= 0xFF:
    raise SystemExit("status must be one byte")
  bits = registry.decode_status_bits(status)
  classifying = [name for bit, name in registry.DTC_STATUS_BITS if status & bit & profile.fault_status_mask]
  print(f"status {status:#04x}: {' '.join(bits) if bits else '(no bits set)'}")
  print(f"fault mask {profile.fault_status_mask:#04x}: {' '.join(classifying) if classifying else '(none)'}")
  return 0


def cmd_active_test_list(args, profile: Profile) -> int:
  ecu = None
  if args.ecu:
    try:
      ecu = profile.lookup_ecu(args.ecu)
    except registry.RegistryError as e:
      raise SystemExit(str(e)) from e
  print(active_test.render_list(profile, ecu))
  return 0


def cmd_active_test_plan(args, profile: Profile) -> int:
  try:
    ecu = profile.lookup_ecu(args.ecu)
    test = profile.lookup_active_test(ecu, args.item, args.kind)
  except registry.RegistryError as e:
    raise SystemExit(str(e)) from e
  print(active_test.render_plan(ecu, test))
  return 0


def cmd_transport_status(args, profile: Profile) -> int:
  live = _live_transport()
  state = live.status(profile)
  if args.json:
    print(json.dumps(state, sort_keys=True))
  else:
    print(f"pandad: {'running' if state['pandad_running'] else 'stopped'}")
    print(f"mode:   {state['mode']}")
    print(f"ready:  {'yes' if state['ready'] else 'no'}")
    print(f"detail: {state['detail']}")
  return 0 if state["ready"] else 1


def cmd_can_sniff(args, profile: Profile) -> int:
  import time
  if args.duration < 0:
    raise SystemExit("--duration must be >= 0 (0 means until interrupted)")
  if args.count < 0:
    raise SystemExit("--count must be >= 0")
  bus = profile.bus if args.bus is None else args.bus
  if not 0 <= bus <= 3:
    raise SystemExit("--bus must be 0..3")
  addresses = {_cli_int(value, "CAN address") for value in args.address}
  if any(not 0 <= address <= 0x1FFFFFFF for address in addresses):
    raise SystemExit("CAN address must fit 29 bits")

  receiver = _live_transport().passive_receiver()
  started = time.monotonic()
  seen = 0
  try:
    while args.duration == 0 or time.monotonic() - started < args.duration:
      frames = receiver.can_recv()
      if not frames:
        time.sleep(0.01)
        continue
      for address, data, recv_bus in frames:
        if recv_bus != bus or address not in addresses:
          continue
        seen += 1
        elapsed = time.monotonic() - started
        if args.json:
          print(json.dumps({
            "sample": seen, "elapsed_s": round(elapsed, 6), "bus": recv_bus,
            "address": address, "data_hex": data.hex(),
          }, sort_keys=True))
        else:
          print(f"[{seen:06d}] +{elapsed:9.3f}s bus={recv_bus} addr=0x{address:X} data={data.hex()}")
        if args.count and seen >= args.count:
          return 0
  except KeyboardInterrupt:
    if not args.json:
      print("stopped")
  return 0


# Live -----------------------------------------------------------------------
def _scan_set(profile: Profile, refs: list[str] | None) -> list[tuple[int, str]]:
  if not refs:
    return [(ecu.address, ecu.name) for ecu in profile.scanned_ecus()]
  try:
    ecus = [profile.lookup_ecu(ref) for ref in refs]
  except registry.RegistryError as e:
    raise SystemExit(str(e)) from e
  return [(ecu.address, ecu.name) for ecu in ecus]


def cmd_dtc_scan(args, profile: Profile) -> int:
  transport = _live_transport()
  panda = transport.connect(profile)
  client_factory = transport.uds_client_factory(panda, profile)
  quiet = (lambda _: None) if args.json else print
  responding, faults = dtc.scan(
    client_factory, _scan_set(profile, args.ecu), profile.fault_status_mask,
    show_all=args.all, echo=quiet,
  )
  if args.json:
    ecus = []
    for address, records in responding.items():
      try:
        ecu = profile.lookup_ecu(address)
        ecu_key, ecu_name = ecu.key, ecu.name
      except registry.RegistryError:
        ecu_key, ecu_name = None, profile.name_for(address)
      items = []
      for code, status in records:
        descriptions = profile.describe_dtc(address, code)
        items.append({
          "code": code,
          "status": status,
          "status_bits": registry.decode_status_bits(status),
          "fault_status": bool(status & profile.fault_status_mask),
          "descriptions": descriptions,
        })
      ecus.append({"key": ecu_key, "name": ecu_name, "address": address, "dtcs": items})
    print(json.dumps({
      "profile": profile.name,
      "fault_status_mask": profile.fault_status_mask,
      "responding_ecus": len(responding),
      "fault_status_records": len(faults),
      "ecus": ecus,
    }, sort_keys=True))
  else:
    print(f"responding ECUs: {len(responding)}; fault-status records: {len(faults)}")
    for address, code, _ in faults:
      try:
        ecu = profile.lookup_ecu(address)
      except registry.RegistryError:
        continue
      for info in profile.describe_dtc(ecu, code):
        print(f"  {ecu.name} {code}: {info.get('description') or ''} — {info.get('failure') or ''}")
  return 1 if faults else 0


def cmd_dtc_clear(args, profile: Profile) -> int:
  import time
  transport = _live_transport()
  panda = transport.connect(profile)
  client_factory = transport.uds_client_factory(panda, profile)
  scan_set = _scan_set(profile, None)

  _guard(profile, client_factory)
  print("\npre-clear scan:")
  responders, faults = dtc.scan(client_factory, scan_set, profile.fault_status_mask)
  print(f"responding ECUs: {len(responders)}; fault-status records: {len(faults)}")

  dtc.clear_physical_uds(client_factory, {address: profile.name_for(address) for address in responders})
  positives = dtc.functional_obd_mode04(panda, profile.legislated_responders, profile.bus)
  if positives != set(profile.legislated_responders):
    print("warning: not all live-validated legislated responders acknowledged Mode 04")

  time.sleep(0.2)
  print("\npost-clear verification:")
  final_responders, final_faults = dtc.scan(client_factory, scan_set, profile.fault_status_mask)
  print(f"responding ECUs: {len(final_responders)}; remaining fault-status records: {len(final_faults)}")
  if final_faults:
    print("FAILED: fault-status DTCs remain")
    return 2
  print("PASS: all responding ECUs are clear of fault-status DTCs")
  return 0


def _resolve_did_queries(profile: Profile, ecu, queries: list[str]) -> list[tuple[int, list[dict[str, Any]]]]:
  resolved: list[tuple[int, list[dict[str, Any]]]] = []
  seen: set[int] = set()
  for query in queries:
    did, signals = profile.resolve_did(ecu, query)
    if did not in seen:
      resolved.append((did, signals))
      seen.add(did)
  return resolved


def _did_value_record(ecu, did: int, signals: list[dict[str, Any]], data: bytes) -> dict[str, Any]:
  decoded = []
  for signal in signals:
    item = {
      "name": signal.get("name") or "",
      "decoder": signal.get("decoder"),
      "bit_start": signal.get("bit_start"),
      "bit_end": signal.get("bit_end"),
      "unit": signal.get("unit"),
    }
    try:
      item.update(decode.decode_signal(data, signal))
    except decode.DecodeError as e:
      item["error"] = str(e)
    decoded.append(item)
  return {
    "ecu": {"key": ecu.key, "name": ecu.name, "address": ecu.address},
    "did": did,
    "data_hex": data.hex(),
    "signals": decoded,
  }


def _print_did_value(ecu, did: int, signals: list[dict[str, Any]], data: bytes, prefix: str = "") -> None:
  printable = "".join(chr(value) if 32 <= value < 127 else "." for value in data)
  print(f"{prefix}{ecu.name} DID 0x{did:04X}: {data.hex()} |{printable}|")
  for signal in signals:
    try:
      print(f"  {decode.format_decoded_signal(data, signal)}")
    except decode.DecodeError as e:
      print(f"  {_format_signal(signal)} — decode unavailable: {e}")


def cmd_did_decode(args, profile: Profile) -> int:
  try:
    ecu = profile.lookup_ecu(args.ecu)
    did, signals = profile.resolve_did(ecu, args.did)
    data = registry.parse_bytes(args.payload, "DID payload")
  except registry.RegistryError as e:
    raise SystemExit(str(e)) from e
  if args.json:
    print(json.dumps(_did_value_record(ecu, did, signals, data), sort_keys=True))
  else:
    _print_did_value(ecu, did, signals, data)
  return 0


def cmd_did_read(args, profile: Profile) -> int:
  try:
    ecu = profile.lookup_ecu(args.ecu)
    dids = _resolve_did_queries(profile, ecu, args.did)
  except registry.RegistryError as e:
    raise SystemExit(str(e)) from e
  transport = _live_transport()
  panda = transport.connect(profile)
  client = transport.uds_client_factory(panda, profile)(ecu.address)
  values = []
  for did, signals in dids:
    data = client.read_data_by_identifier(did)
    if args.json:
      values.append(_did_value_record(ecu, did, signals, data))
    else:
      _print_did_value(ecu, did, signals, data)
  if args.json:
    print(json.dumps({"values": values}, sort_keys=True))
  return 0


def cmd_did_watch(args, profile: Profile) -> int:
  import time
  if args.interval < 0:
    raise SystemExit("--interval must be >= 0")
  if args.count < 0:
    raise SystemExit("--count must be >= 0 (0 means until interrupted)")
  try:
    ecu = profile.lookup_ecu(args.ecu)
    dids = _resolve_did_queries(profile, ecu, args.did)
  except registry.RegistryError as e:
    raise SystemExit(str(e)) from e

  transport = _live_transport()
  panda = transport.connect(profile)
  client = transport.uds_client_factory(panda, profile)(ecu.address)
  started = time.monotonic()
  sample = 0
  try:
    while args.count == 0 or sample < args.count:
      values = []
      for did, signals in dids:
        data = client.read_data_by_identifier(did)
        if args.json:
          values.append(_did_value_record(ecu, did, signals, data))
        else:
          _print_did_value(ecu, did, signals, data, prefix=f"[{sample + 1:04d}] ")
      sample += 1
      elapsed = time.monotonic() - started
      if args.json:
        print(json.dumps({"sample": sample, "elapsed_s": round(elapsed, 6), "values": values}, sort_keys=True))
      elif len(dids) > 1:
        print(f"  sample {sample} complete +{elapsed:.3f}s")
      if args.count == 0 or sample < args.count:
        time.sleep(args.interval)
  except KeyboardInterrupt:
    if not args.json:
      print("stopped")
  return 0


def cmd_uds_raw(args, profile: Profile) -> int:
  service = _cli_int(args.service, "service")
  if not 0 < service <= 0xFF:
    raise SystemExit("service must be one byte")
  subfunction = None if args.subfunction is None else _cli_int(args.subfunction, "subfunction")
  if subfunction is not None and not 0 <= subfunction <= 0xFF:
    raise SystemExit("subfunction must be one byte")
  try:
    data = registry.parse_bytes(args.data, "data") if args.data else b""
    ecu = profile.lookup_ecu(args.ecu)
  except registry.RegistryError as e:
    raise SystemExit(str(e)) from e
  mutating = service not in READ_ONLY_UDS_SERVICES
  if mutating and not args.force:
    raise SystemExit(f"refusing mutating service 0x{service:02X}; pass --force (identity guard still applies)")

  transport = _live_transport()
  panda = transport.connect(profile)
  client_factory = transport.uds_client_factory(panda, profile)
  if mutating:
    _guard(profile, client_factory)
  request = bytes([service]) + (bytes([subfunction]) if subfunction is not None else b"") + data
  response = transport.raw_isotp(client_factory(ecu.address), request)
  print(f"request:  {request.hex()}")
  print(f"response: {response.hex()}")
  return 0


def cmd_functional_obd(args, profile: Profile) -> int:
  mode = _cli_int(args.mode, "mode")
  if not 0 < mode <= 0xFF:
    raise SystemExit("mode must be one byte")
  try:
    payload = registry.parse_bytes(args.payload, "payload") if args.payload else b""
  except registry.RegistryError as e:
    raise SystemExit(str(e)) from e
  if len(payload) > 6:
    raise SystemExit("payload longer than six bytes does not fit the standard 8-byte functional frame")
  mutating = mode not in READ_ONLY_OBD_MODES
  if mutating and not args.force:
    raise SystemExit(f"refusing mutating OBD mode 0x{mode:02X}; pass --force (identity guard still applies)")

  transport = _live_transport()
  panda = transport.connect(profile)
  if mutating:
    _guard(profile, transport.uds_client_factory(panda, profile))
  positives = dtc.functional_obd_request(panda, mode, payload, profile.legislated_responders, profile.bus, args.window)
  missing = set(profile.legislated_responders) - positives
  if missing:
    print(f"warning: no positive response from {' '.join(f'{address:#05x}' for address in sorted(missing))}")
  return 0


def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(prog="toyota", description="Toyota/GTS-derived diagnostics on a Comma Panda")
  parser.add_argument(
    "--registry", default=str(registry.DEFAULT_REGISTRY), metavar="FILE",
    help="derived registry JSON (default: bundled Camry F33 profile)",
  )
  commands = parser.add_subparsers(dest="command", required=True)

  transport_parser = commands.add_parser("transport")
  transport_sub = transport_parser.add_subparsers(required=True)
  p = transport_sub.add_parser("status")
  p.add_argument("--json", action="store_true")
  p.set_defaults(func=cmd_transport_status)

  can_parser = commands.add_parser("can")
  can_sub = can_parser.add_subparsers(required=True)
  p = can_sub.add_parser("sniff")
  p.add_argument("address", nargs="+", help="one or more 11/29-bit CAN addresses")
  p.add_argument("--bus", type=int, help="Panda bus (default: profile diagnostic bus)")
  p.add_argument("--duration", type=float, default=5.0, help="seconds to capture; 0 means until interrupted (default: 5)")
  p.add_argument("--count", type=int, default=0, help="stop after this many matching frames; 0 means no count limit")
  p.add_argument("--json", action="store_true", help="emit one JSON object per matching frame")
  p.set_defaults(func=cmd_can_sniff)

  ecu = commands.add_parser("ecu")
  ecu_sub = ecu.add_subparsers(required=True)
  p = ecu_sub.add_parser("list")
  p.set_defaults(func=cmd_ecu_list)
  p = ecu_sub.add_parser("info")
  p.add_argument("ecu")
  p.set_defaults(func=cmd_ecu_info)

  did = commands.add_parser("did")
  did_sub = did.add_subparsers(required=True)
  p = did_sub.add_parser("list")
  p.add_argument("ecu")
  p.add_argument("query", nargs="?")
  p.add_argument("--limit", type=int, default=100)
  p.set_defaults(func=cmd_did_list)
  p = did_sub.add_parser("decode")
  p.add_argument("ecu")
  p.add_argument("did")
  p.add_argument("payload", help="DID value bytes as hex; positive SID/DID echo excluded")
  p.add_argument("--json", action="store_true")
  p.set_defaults(func=cmd_did_decode)
  p = did_sub.add_parser("read")
  p.add_argument("ecu")
  p.add_argument("did", nargs="+", help="one or more DID numbers or GTS names")
  p.add_argument("--json", action="store_true")
  p.set_defaults(func=cmd_did_read)
  p = did_sub.add_parser("watch")
  p.add_argument("ecu")
  p.add_argument("did", nargs="+", help="one or more DID numbers or GTS names")
  p.add_argument("--interval", type=float, default=0.25, help="seconds between sample groups (default: 0.25)")
  p.add_argument("--count", type=int, default=0, help="number of sample groups; 0 means until interrupted")
  p.add_argument("--json", action="store_true", help="emit one JSON object per sample group")
  p.set_defaults(func=cmd_did_watch)

  dtc_parser = commands.add_parser("dtc")
  dtc_sub = dtc_parser.add_subparsers(required=True)
  p = dtc_sub.add_parser("catalog")
  p.add_argument("ecu")
  p.add_argument("query", nargs="?")
  p.add_argument("--limit", type=int, default=100)
  p.set_defaults(func=cmd_dtc_catalog)
  p = dtc_sub.add_parser("decode")
  p.add_argument("status")
  p.set_defaults(func=cmd_dtc_decode)
  p = dtc_sub.add_parser("scan")
  p.add_argument("--all", action="store_true")
  p.add_argument("--ecu", action="append")
  p.add_argument("--json", action="store_true", help="emit one machine-readable DTC snapshot")
  p.set_defaults(func=cmd_dtc_scan)
  p = dtc_sub.add_parser("clear")
  p.set_defaults(func=cmd_dtc_clear)

  uds = commands.add_parser("uds")
  uds_sub = uds.add_subparsers(required=True)
  p = uds_sub.add_parser("raw")
  p.add_argument("ecu")
  p.add_argument("service")
  p.add_argument("data", nargs="?")
  p.add_argument("--subfunction")
  p.add_argument("--force", action="store_true")
  p.set_defaults(func=cmd_uds_raw)

  functional = commands.add_parser("functional")
  functional_sub = functional.add_subparsers(required=True)
  p = functional_sub.add_parser("obd")
  p.add_argument("mode")
  p.add_argument("payload", nargs="?")
  p.add_argument("--window", type=float, default=1.0)
  p.add_argument("--force", action="store_true")
  p.set_defaults(func=cmd_functional_obd)

  at = commands.add_parser("active-test")
  at_sub = at.add_subparsers(required=True)
  p = at_sub.add_parser("list")
  p.add_argument("ecu", nargs="?")
  p.set_defaults(func=cmd_active_test_list)
  p = at_sub.add_parser("plan")
  p.add_argument("ecu")
  p.add_argument("item")
  p.add_argument("--kind", choices=("direct", "routine"))
  p.set_defaults(func=cmd_active_test_plan)
  return parser


def main(argv: list[str] | None = None) -> int:
  args = build_parser().parse_args(argv)
  return int(args.func(args, _profile(args)))


if __name__ == "__main__":
  sys.exit(main())
