"""Unified Comma-side Toyota diagnostic CLI."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from tools.toyota_diag import active_test, decode, discovery, dtc, executor, monitor, registry, snapshot, utility
from tools.toyota_diag.registry import Profile
from tools.toyota_diag.session import DiagnosticSession, LifecycleError

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


def _json_or_text(args, document: Any, text: str) -> int:
  if getattr(args, "json", False):
    print(json.dumps(document, sort_keys=True))
  else:
    print(text)
  return 0


# Offline --------------------------------------------------------------------
def cmd_search(args, profile: Profile) -> int:
  rows = discovery.search(profile, args.query, args.limit)
  if args.json:
    document = [{
      "kind": row.kind,
      "ecu": row.ecu.key if row.ecu else None,
      "ecu_name": row.ecu.name if row.ecu else None,
      "identifier": row.identifier,
      "name": row.name,
      "detail": row.detail,
    } for row in rows]
    print(json.dumps(document, sort_keys=True))
  else:
    print(discovery.render(rows))
  return 0 if rows else 1


def cmd_vehicle_show(args, profile: Profile) -> int:
  document = {
    "profile": profile.name,
    "vehicle": profile.vehicle,
    "panda_bus": profile.bus,
    "registry": str(profile.path),
    "identity_guard": {
      "ecu": profile.guard.ecu_key,
      "did": profile.guard.did,
      "contains_ascii": profile.guard.contains_ascii,
    },
  }
  text = "\n".join((
    profile.vehicle,
    f"profile:  {profile.name}",
    f"registry: {profile.path}",
    f"Panda bus: {profile.bus}",
    f"guard:    {profile.guard.ecu_key} DID 0x{profile.guard.did:04X} contains {profile.guard.contains_ascii}",
  ))
  return _json_or_text(args, document, text)


def cmd_vehicle_list(args, profile: Profile) -> int:
  rows = []
  for path in registry.available_registries(profile.path.parent):
    try:
      item = registry.load_registry(path)
    except registry.RegistryError:
      continue
    rows.append({"profile": item.name, "vehicle": item.vehicle, "path": str(path), "default": path.resolve() == profile.path.resolve()})
  if args.json:
    print(json.dumps(rows, sort_keys=True))
  else:
    for row in rows:
      mark = "*" if row["default"] else " "
      print(f"{mark} {row['profile']:<22} {row['vehicle']}")
  return 0


def cmd_vehicle_detect(args, profile: Profile) -> int:
  live = _live_transport()
  candidates = []
  for path in registry.available_registries(profile.path.parent):
    try:
      candidates.append(registry.load_registry(path))
    except registry.RegistryError:
      continue
  matches = []
  errors = []
  for candidate in candidates:
    try:
      panda = live.connect(candidate)
      factory = live.uds_client_factory(panda, candidate)
      ecu = candidate.lookup_ecu(candidate.guard.ecu_key)
      data = factory(ecu.address).read_data_by_identifier(candidate.guard.did)
      if candidate.guard.contains in data:
        matches.append({"profile": candidate.name, "vehicle": candidate.vehicle, "guard_data_hex": bytes(data).hex()})
    except Exception as e:
      errors.append({"profile": candidate.name, "error": str(e)})
  document = {"matches": matches, "errors": errors}
  if args.json:
    print(json.dumps(document, sort_keys=True))
  else:
    if matches:
      for row in matches:
        print(f"✓ {row['profile']}: {row['vehicle']}")
    else:
      print("no bundled profile matched the live identity guard")
    for row in errors:
      if args.verbose:
        print(f"  {row['profile']}: {row['error']}")
  return 0 if matches else 1


def cmd_ecu_functions(args, profile: Profile) -> int:
  try:
    ecu = profile.lookup_ecu(args.ecu)
  except registry.RegistryError as e:
    raise SystemExit(str(e)) from e
  rows = profile.functions(ecu)
  if not rows:
    print("registry has no compiled function hierarchy for this ECU")
    return 1
  for row in rows[:args.limit]:
    ident = row.get("id") or row.get("function_id") or "?"
    details = row.get("detail_ids")
    if isinstance(details, list) and details:
      detail = " details=" + ",".join(f"0x{int(value):X}" for value in details)
    elif row.get("detail_id") is not None:
      detail = f" detail=0x{int(row['detail_id']):X}"
    else:
      detail = ""
    name = row.get("name") or row.get("detail_name") or "(OEM name unrecovered)"
    semantic = row.get("semantic_kind") or row.get("kind") or ""
    suffix = f" — {semantic}" if semantic else ""
    print(f"0x{int(ident):X}  {name}{detail}{suffix}")
  return 0


def cmd_ecu_plugins(args, profile: Profile) -> int:
  try:
    ecu = profile.lookup_ecu(args.ecu)
  except registry.RegistryError as e:
    raise SystemExit(str(e)) from e
  rows = profile.roles(ecu)
  if not rows:
    print("registry has no compiled plugin/role bindings for this ECU")
    return 1
  for row in rows[:args.limit]:
    role = row.get("role") or row.get("id") or 0
    dll = row.get("dll") or row.get("plugin") or row.get("name") or "(unknown DLL)"
    semantic = row.get("semantic_kind") or row.get("kind") or "opaque"
    status = row.get("semantic_status") or ""
    suffix = f" [{status}]" if status else ""
    print(f"0x{int(role):02X}  {semantic:<34} {dll}{suffix}")
  return 0


def cmd_ecu_data(args, profile: Profile) -> int:
  args.query = args.query if hasattr(args, "query") else None
  return cmd_did_list(args, profile)


def cmd_ecu_dtcs(args, profile: Profile) -> int:
  args.query = args.query if hasattr(args, "query") else None
  return cmd_dtc_catalog(args, profile)


def cmd_ecu_active_tests(args, profile: Profile) -> int:
  args.ecu = args.ecu
  return cmd_active_test_list(args, profile)


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
    counts = discovery.summary_counts(profile, ecu)
    print(f"GTS DB:    {meta['database']} ({meta['name']})")
    print(f"Data List: {counts['dids']} DID(s), {counts['signals']} signal(s)")
    print(f"DTCs:      {counts['dtcs']}")
    print(f"Active Tests: {counts['active_tests']} candidate(s)")
    if counts["functions"] or counts["roles"]:
      print(f"Functions: {counts['functions']}  Plugins: {counts['roles']}  Concrete utilities: {counts['utilities']}")
  identity = profile.observed_identity(ecu)
  if identity is not None:
    print(f"observed:  {identity['observation']}")
    print(f"F181:      {', '.join(identity['f181_software_ids'])}")
    if identity.get("ecu_part_0105"):
      print(f"part 0105: {identity['ecu_part_0105']}")
    print(f"F18C:      {identity['f18c_serial']}")
    print(f"obs route: Panda bus {identity['panda_bus_at_observation']}, ELM327 param {identity['elm327_param']}")
    print(f"route note: {identity['route_note']}")
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
  print(active_test.render_plan(profile, ecu, test))
  return 0


def _optional_bytes(value: str | None, what: str) -> bytes | None:
  if value is None:
    return None
  try:
    return registry.parse_bytes(value, what)
  except registry.RegistryError as e:
    raise SystemExit(str(e)) from e


def _result_document(result: executor.ActiveTestResult, cleanup_errors: tuple[str, ...] = ()) -> dict[str, Any]:
  errors = list(dict.fromkeys((*result.cleanup_errors, *cleanup_errors)))
  return {
    "ecu": result.plan.ecu.key,
    "test_id": result.plan.test_id,
    "name": result.plan.name,
    "kind": result.plan.kind,
    "executed": result.executed,
    "session_requirement": result.session_requirement,
    "start_response_hex": result.start.hex() if result.start is not None else None,
    "status_responses": [{"time_s": stamp, "response_hex": data.hex()} for stamp, data in result.statuses],
    "stop_response_hex": result.stop.hex() if result.stop is not None else None,
    "cleanup_errors": errors,
  }


def _exception_cleanup_errors(error: BaseException, session: DiagnosticSession) -> tuple[str, ...]:
  attached = getattr(error, "toyota_cleanup_errors", ())
  return tuple(dict.fromkeys((*attached, *session.cleanup_errors)))


def _report_exception_cleanup(error: BaseException, session: DiagnosticSession) -> None:
  errors = _exception_cleanup_errors(error, session)
  if errors:
    print("CLEANUP ERROR(S):", file=sys.stderr)
    for message in errors:
      print(f"  {message}", file=sys.stderr)


def _render_result(result: executor.ActiveTestResult, cleanup_errors: tuple[str, ...] = ()) -> str:
  document = _result_document(result, cleanup_errors)
  lines = [
    f"{result.plan.ecu.key} 0x{result.plan.test_id:04X} {result.plan.name}",
    f"executed: {'yes' if result.executed else 'no'}",
  ]
  if document["start_response_hex"] is not None:
    lines.append(f"start response: {document['start_response_hex']}")
  for status in document["status_responses"]:
    lines.append(f"status @{status['time_s']:.3f}: {status['response_hex']}")
  if document["stop_response_hex"] is not None:
    lines.append(f"stop response:  {document['stop_response_hex']}")
  if document["cleanup_errors"]:
    lines.append("CLEANUP ERROR(S):")
    lines.extend(f"  {message}" for message in document["cleanup_errors"])
  return "\n".join(lines)


def _active_test_lookup(profile: Profile, args) -> tuple[Any, dict[str, Any], executor.TestPlan]:
  try:
    ecu = profile.lookup_ecu(args.ecu)
    row = profile.lookup_active_test(ecu, args.item, getattr(args, "kind", None))
  except registry.RegistryError as e:
    raise SystemExit(str(e)) from e
  return ecu, row, executor.resolve_plan(ecu, row)


def cmd_active_test_run(args, profile: Profile) -> int:
  ecu, row, plan = _active_test_lookup(profile, args)
  if not args.execute:
    print(active_test.render_plan(profile, ecu, row))
    print("\nDRY RUN: no request sent; pass --execute to acknowledge mutation")
    return 0
  if args.hold <= 0:
    raise SystemExit("--hold must be > 0 seconds")
  if args.poll_interval <= 0:
    raise SystemExit("--poll-interval must be > 0 seconds")
  refusals = executor.runtime_refusals(profile, plan)
  if refusals:
    raise SystemExit("Active Test refused before transport: " + "; ".join(refusals))
  option_record = _optional_bytes(args.option_record, "--option-record")
  value_payload = _optional_bytes(args.value, "--value") or b""
  control_mask = _optional_bytes(args.mask, "--mask") or b""

  live = _live_transport()
  panda = live.connect(profile)
  session = DiagnosticSession(profile, ecu, panda=panda, operation_row=row)
  try:
    with session:
      if isinstance(plan, executor.RoutineTestPlan):
        result = executor.run_routine_test(
          session, plan, hold_s=args.hold, option_record=option_record, execute=True,
          poll_interval_s=args.poll_interval,
        )
      elif isinstance(plan, executor.DirectTestPlan):
        if option_record is not None:
          raise executor.ExecutorError("direct Active Tests do not take --option-record; use --value and --mask")
        result = executor.run_direct_test(
          session, plan, hold_s=args.hold, value_payload=value_payload,
          control_enable_mask=control_mask, execute=True,
        )
      else:
        raise executor.PlanNotExecutable(plan, executor.runtime_refusals(profile, plan))
  except KeyboardInterrupt as e:
    _report_exception_cleanup(e, session)
    print("interrupted; emergency stop and default-session cleanup were attempted", file=sys.stderr)
    return 130
  except SystemExit as e:
    _report_exception_cleanup(e, session)
    raise
  except (executor.ExecutorError, LifecycleError, registry.RegistryError) as e:
    _report_exception_cleanup(e, session)
    raise SystemExit(f"Active Test refused/failed: {e}") from e
  except Exception as e:
    _report_exception_cleanup(e, session)
    raise SystemExit(f"Active Test failed after cleanup attempt: {e}") from e

  cleanup_errors = tuple(session.cleanup_errors)
  if args.json:
    print(json.dumps(_result_document(result, cleanup_errors), sort_keys=True))
  else:
    print(_render_result(result, cleanup_errors))
  return 3 if _result_document(result, cleanup_errors)["cleanup_errors"] else 0


def cmd_active_test_stop(args, profile: Profile) -> int:
  ecu, row, plan = _active_test_lookup(profile, args)
  if not args.execute:
    print(active_test.render_plan(profile, ecu, row))
    print("\nSTOP PLAN ONLY: no request sent; pass --execute to acknowledge recovery mutation")
    return 0
  refusals = executor.runtime_refusals(profile, plan)
  if refusals:
    raise SystemExit("Active Test stop refused before transport: " + "; ".join(refusals))
  control_mask = _optional_bytes(args.mask, "--mask") or b""
  live = _live_transport()
  panda = live.connect(profile)
  session = DiagnosticSession(profile, ecu, panda=panda, operation_row=row)
  try:
    with session:
      result = executor.stop_test(session, plan, control_enable_mask=control_mask, execute=True)
  except SystemExit as e:
    _report_exception_cleanup(e, session)
    raise
  except (executor.ExecutorError, LifecycleError, registry.RegistryError) as e:
    _report_exception_cleanup(e, session)
    raise SystemExit(f"Active Test stop refused/failed: {e}") from e
  except Exception as e:
    _report_exception_cleanup(e, session)
    raise SystemExit(f"Active Test stop failed after cleanup attempt: {e}") from e
  cleanup_errors = tuple(session.cleanup_errors)
  if args.json:
    print(json.dumps(_result_document(result, cleanup_errors), sort_keys=True))
  else:
    print(_render_result(result, cleanup_errors))
  return 3 if _result_document(result, cleanup_errors)["cleanup_errors"] else 0


def cmd_utility_list(args, profile: Profile) -> int:
  families = utility.list_families(profile)
  document: dict[str, Any] = {
    "boundary": (profile.utility_metadata or {}).get("boundary"),
    "families": families,
  }
  concrete = []
  if args.ecu:
    try:
      ecu = profile.lookup_ecu(args.ecu)
    except registry.RegistryError as e:
      raise SystemExit(str(e)) from e
    concrete = profile.utilities(ecu)
    document["ecu"] = ecu.key
    document["concrete"] = concrete
  if args.json:
    print(json.dumps(document, sort_keys=True))
    return 0
  print("Recovered generic utility families (metadata only):")
  for row in families:
    print(f"  0x{int(row['role']):02X}  {row.get('semantic_kind') or '(opaque)':<34} {row.get('dll') or ''}")
  boundary = document.get("boundary")
  if boundary:
    print(f"boundary: {boundary}")
  if args.ecu:
    print(f"concrete {args.ecu} utilities: {len(concrete)}")
    for row in concrete:
      print(f"  0x{int(row.get('id', 0)):04X}  {row.get('name') or ''} [{row.get('execution') or 'unknown'}]")
  return 0


def cmd_utility_plan(args, profile: Profile) -> int:
  try:
    family = utility.plan_family(profile, args.item)
  except registry.RegistryError as e:
    raise SystemExit(str(e)) from e
  metadata = profile.utility_metadata or {}
  semantic = str(family.get("semantic_kind") or "")
  template = None
  if "routine" in semantic:
    template = metadata.get("routine_control")
  elif semantic == "active_test_start":
    template = metadata.get("io_control")
  document = {"family": family, "template": template, "boundary": metadata.get("boundary")}
  if args.json:
    print(json.dumps(document, sort_keys=True))
  else:
    print(f"role: 0x{int(family['role']):02X}")
    print(f"semantic: {semantic or '(opaque)'}")
    print(f"DLL: {family.get('dll') or ''}")
    if template:
      for key, value in template.items():
        print(f"{key}: {value}")
    print("runtime: metadata/plan only; no concrete per-ECU utility operation is authorized by this family binding")
  return 0


def cmd_utility_run(args, profile: Profile) -> int:
  try:
    ecu = profile.lookup_ecu(args.ecu)
    plan = utility.plan_utility(profile, ecu, args.item, kind=args.kind)
  except registry.RegistryError as e:
    boundary = (profile.utility_metadata or {}).get("boundary")
    suffix = f"; registry boundary: {boundary}" if boundary else ""
    raise SystemExit(f"no concrete executable utility resolved: {e}{suffix}") from e
  if not args.execute:
    print(f"{plan.describe()}\nDRY RUN: no request sent; pass --execute to acknowledge mutation")
    return 0
  if args.hold <= 0:
    raise SystemExit("--hold must be > 0 seconds")
  refusals = executor.runtime_refusals(profile, plan)
  if refusals:
    raise SystemExit("utility refused before transport: " + "; ".join(refusals))
  option_record = _optional_bytes(args.option_record, "--option-record")
  value_payload = _optional_bytes(args.value, "--value") or b""
  control_mask = _optional_bytes(args.mask, "--mask") or b""
  live = _live_transport()
  panda = live.connect(profile)
  session = DiagnosticSession(profile, ecu, panda=panda)
  try:
    with session:
      result = utility.run_utility(
        session, plan, hold_s=args.hold, execute=True, option_record=option_record,
        value_payload=value_payload, control_enable_mask=control_mask,
        poll_interval_s=args.poll_interval,
      )
  except SystemExit as e:
    _report_exception_cleanup(e, session)
    raise
  except (executor.ExecutorError, LifecycleError, registry.RegistryError) as e:
    _report_exception_cleanup(e, session)
    raise SystemExit(f"utility refused/failed: {e}") from e
  except Exception as e:
    _report_exception_cleanup(e, session)
    raise SystemExit(f"utility failed after cleanup attempt: {e}") from e
  cleanup_errors = tuple(session.cleanup_errors)
  if args.json:
    print(json.dumps(_result_document(result, cleanup_errors), sort_keys=True))
  else:
    print(_render_result(result, cleanup_errors))
  return 3 if _result_document(result, cleanup_errors)["cleanup_errors"] else 0


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


def cmd_can_topology(args, profile: Profile) -> int:
  topology = profile.gts_can_topology
  if topology is None:
    raise SystemExit("registry does not carry GTS CAN topology")
  if args.json:
    print(json.dumps(topology, sort_keys=True))
    return 0

  print(f"Toyota GTS topology: {topology['vehicle_name']} type={topology['vehicle_type']} CANBusCarID={topology['can_bus_car_id']}")
  print(f"options={topology['option_count']} placement_variants={topology['placement_variant_count']}")
  placements = topology["placement_variants"][0]["placements"]
  buses: dict[str, list[dict[str, Any]]] = {}
  for row in placements:
    buses.setdefault(row["bus_name"], []).append(row)
  for bus_name, rows in sorted(buses.items(), key=lambda item: min(row["bus_index"] for row in item[1])):
    print(f"{bus_name}:")
    for row in rows:
      gateways = f" via {', '.join(row['gateway_names'])}" if row["gateway_names"] else ""
      junction = f" @ {row['junction_name']}" if row["junction_name"] and row["junction_name"] != "-" else ""
      print(f"  {row['component_hex']}  {row['ecu_domain']}{gateways}{junction}")
  print(f"boundary: {topology['namespace_boundary']}")
  return 0


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


def _resolve_monitor_queries(profile: Profile, ecu, queries: list[str]) -> list[tuple[int, list[dict[str, Any]]]]:
  if not queries:
    raise registry.RegistryError("monitor requires at least one DID number or Data List search term")
  out: list[tuple[int, list[dict[str, Any]]]] = []
  seen: set[int] = set()
  for query in queries:
    try:
      matches = [profile.resolve_did(ecu, query)]
    except registry.RegistryError as exact_error:
      needle = query.casefold()
      matches = [
        (int(key, 16), rows)
        for key, rows in profile.dids(ecu).items()
        if any(needle in str(row.get("name") or "").casefold() for row in rows)
      ]
      if not matches:
        raise exact_error
    for did, signals in matches:
      if did not in seen:
        out.append((did, signals))
        seen.add(did)
  return out


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


def cmd_monitor(args, profile: Profile) -> int:
  import time
  try:
    ecu = profile.lookup_ecu(args.ecu)
    dids = _resolve_monitor_queries(profile, ecu, args.item)
  except registry.RegistryError as e:
    raise SystemExit(str(e)) from e
  transport = _live_transport()
  panda = transport.connect(profile)
  session = DiagnosticSession(profile, ecu, panda=panda)

  try:
    with session:
      lifecycle = session.lifecycle
      proven = (
        lifecycle is not None
        and (lifecycle.wire_proven_categories is None or ecu.category_id in lifecycle.wire_proven_categories)
      )
      if proven:
        # This is read-only Data Monitor lifecycle, not actuator authorization: mirror
        # Techstream's recovered D1→D2 entry and deterministically restore D1 on exit.
        session.enter_extended(acknowledge=True)
      client = session.client()
      keepalive = lifecycle.keepalive if proven and lifecycle is not None else None
      next_keepalive = time.monotonic() + keepalive.interval_s if keepalive is not None else float("inf")

      def read_values():
        nonlocal next_keepalive
        now = time.monotonic()
        if keepalive is not None and now >= next_keepalive:
          session.keepalive()
          next_keepalive = now + keepalive.interval_s
        return [_did_value_record(ecu, did, signals, client.read_data_by_identifier(did)) for did, signals in dids]

      return monitor.run(
        ecu.name, read_values,
        interval=args.interval,
        count=args.count,
        changed=args.changed,
        jsonl=args.jsonl,
        csv_output=args.csv,
        clear=False if args.no_clear else None,
      )
  except (ValueError, LifecycleError, registry.RegistryError) as e:
    raise SystemExit(f"monitor refused/failed: {e}") from e


def cmd_scan(args, profile: Profile) -> int:
  transport = _live_transport()
  state = transport.status(profile)
  panda = transport.connect(profile)
  client_factory = transport.uds_client_factory(panda, profile)
  document = snapshot.build(profile, client_factory, state, show_all_dtcs=args.all_dtcs)
  if args.json:
    print(json.dumps(document, sort_keys=True))
  else:
    print(snapshot.render(document))
  return 1 if document["fault_status_records"] else 0


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
    "--registry", "--profile", dest="registry", default=str(registry.DEFAULT_REGISTRY), metavar="PROFILE_OR_FILE",
    help="derived profile name or registry JSON (default: bundled Camry F33 profile)",
  )
  commands = parser.add_subparsers(dest="command", required=True)

  p = commands.add_parser("search", help="search ECUs, Data List items, DTCs, functions, and Active Tests")
  p.add_argument("query")
  p.add_argument("--limit", type=int, default=50)
  p.add_argument("--json", action="store_true")
  p.set_defaults(func=cmd_search)

  vehicle = commands.add_parser("vehicle", help="show, list, or detect vehicle profiles")
  vehicle.add_argument("--json", action="store_true", help="emit the default vehicle summary as JSON")
  vehicle_sub = vehicle.add_subparsers(required=False)
  p = vehicle_sub.add_parser("show")
  p.add_argument("--json", action="store_true")
  p.set_defaults(func=cmd_vehicle_show)
  p = vehicle_sub.add_parser("list")
  p.add_argument("--json", action="store_true")
  p.set_defaults(func=cmd_vehicle_list)
  p = vehicle_sub.add_parser("detect")
  p.add_argument("--json", action="store_true")
  p.add_argument("--verbose", action="store_true")
  p.set_defaults(func=cmd_vehicle_detect)
  vehicle.set_defaults(func=cmd_vehicle_show, json=False)

  p = commands.add_parser("scan", help="read-only vehicle inventory, identity, and DTC snapshot")
  p.add_argument("--json", action="store_true")
  p.add_argument("--all-dtcs", action="store_true", help="preserve non-fault-status DTC records too")
  p.set_defaults(func=cmd_scan)

  p = commands.add_parser("monitor", help="live decoded Techstream Data List monitor")
  p.add_argument("ecu")
  p.add_argument("item", nargs="+", help="DID numbers, exact names, or broad Data List search terms")
  p.add_argument("--interval", type=float, default=0.25)
  p.add_argument("--count", type=int, default=0, help="sample groups; 0 means until interrupted")
  p.add_argument("--changed", action="store_true", help="show only signals whose value changed")
  output = p.add_mutually_exclusive_group()
  output.add_argument("--jsonl", action="store_true", help="emit one JSON object per sample group")
  output.add_argument("--csv", action="store_true", help="emit one CSV row per decoded signal sample")
  p.add_argument("--no-clear", action="store_true", help="never redraw an interactive terminal in-place")
  p.set_defaults(func=cmd_monitor)

  transport_parser = commands.add_parser("transport")
  transport_sub = transport_parser.add_subparsers(required=True)
  p = transport_sub.add_parser("status")
  p.add_argument("--json", action="store_true")
  p.set_defaults(func=cmd_transport_status)

  can_parser = commands.add_parser("can")
  can_sub = can_parser.add_subparsers(required=True)
  p = can_sub.add_parser("topology")
  p.add_argument("--json", action="store_true")
  p.set_defaults(func=cmd_can_topology)
  p = can_sub.add_parser("sniff")
  p.add_argument("address", nargs="+", help="one or more 11/29-bit CAN addresses")
  p.add_argument("--bus", type=int, help="Panda bus (default: profile diagnostic bus)")
  p.add_argument("--duration", type=float, default=5.0, help="seconds to capture; 0 means until interrupted (default: 5)")
  p.add_argument("--count", type=int, default=0, help="stop after this many matching frames; 0 means no count limit")
  p.add_argument("--json", action="store_true", help="emit one JSON object per matching frame")
  p.set_defaults(func=cmd_can_sniff)

  ecu = commands.add_parser("ecu", help="browse one ECU or list known ECUs")
  ecu_sub = ecu.add_subparsers(required=True)
  p = ecu_sub.add_parser("list")
  p.set_defaults(func=cmd_ecu_list)
  p = ecu_sub.add_parser("info")
  p.add_argument("ecu")
  p.set_defaults(func=cmd_ecu_info)
  p = ecu_sub.add_parser("functions")
  p.add_argument("ecu")
  p.add_argument("--limit", type=int, default=100)
  p.set_defaults(func=cmd_ecu_functions)
  p = ecu_sub.add_parser("plugins", help="show recovered GTS role → plugin bindings")
  p.add_argument("ecu")
  p.add_argument("--limit", type=int, default=100)
  p.set_defaults(func=cmd_ecu_plugins)
  p = ecu_sub.add_parser("data")
  p.add_argument("ecu")
  p.add_argument("query", nargs="?")
  p.add_argument("--limit", type=int, default=100)
  p.set_defaults(func=cmd_ecu_data)
  p = ecu_sub.add_parser("dtcs")
  p.add_argument("ecu")
  p.add_argument("query", nargs="?")
  p.add_argument("--limit", type=int, default=100)
  p.set_defaults(func=cmd_ecu_dtcs)
  p = ecu_sub.add_parser("active-tests")
  p.add_argument("ecu")
  p.set_defaults(func=cmd_ecu_active_tests)

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

  at = commands.add_parser("active-test", help="browse, plan, run, or stop recovered Active Tests")
  at_sub = at.add_subparsers(required=True)
  p = at_sub.add_parser("list")
  p.add_argument("ecu", nargs="?")
  p.set_defaults(func=cmd_active_test_list)
  p = at_sub.add_parser("plan")
  p.add_argument("ecu")
  p.add_argument("item")
  p.add_argument("--kind", choices=("direct", "routine"))
  p.set_defaults(func=cmd_active_test_plan)
  p = at_sub.add_parser("run", help="run only a runtime-authorized recovered Active Test")
  p.add_argument("ecu")
  p.add_argument("item")
  p.add_argument("--kind", choices=("direct", "routine"))
  p.add_argument("--hold", type=float, default=1.0, help="seconds to hold the operation before stop (default: 1.0)")
  p.add_argument("--poll-interval", type=float, default=0.5, help="routine status-poll interval in seconds")
  p.add_argument("--option-record", help="explicit routine option-record bytes as hex")
  p.add_argument("--value", help="explicit direct-test value payload bytes as hex")
  p.add_argument("--mask", help="explicit direct-test control-enable mask bytes as hex")
  p.add_argument("--execute", action="store_true", help="acknowledge vehicle mutation; omitted means dry-run only")
  p.add_argument("--json", action="store_true")
  p.set_defaults(func=cmd_active_test_run)
  p = at_sub.add_parser("stop", help="send only the recovered stop/return-control request")
  p.add_argument("ecu")
  p.add_argument("item")
  p.add_argument("--kind", choices=("direct", "routine"))
  p.add_argument("--mask", help="direct-test control-enable mask bytes as hex")
  p.add_argument("--execute", action="store_true", help="acknowledge recovery mutation; omitted means dry-run only")
  p.add_argument("--json", action="store_true")
  p.set_defaults(func=cmd_active_test_stop)

  util = commands.add_parser("utility", help="browse recovered generic utility families and concrete utility plans")
  util_sub = util.add_subparsers(required=True)
  p = util_sub.add_parser("list")
  p.add_argument("ecu", nargs="?", help="optionally include concrete utilities for one ECU")
  p.add_argument("--json", action="store_true")
  p.set_defaults(func=cmd_utility_list)
  p = util_sub.add_parser("plan")
  p.add_argument("item", help="generic utility semantic kind, DLL substring, or role")
  p.add_argument("--json", action="store_true")
  p.set_defaults(func=cmd_utility_plan)
  p = util_sub.add_parser("run", help="run a concrete per-ECU utility row when one is recovered")
  p.add_argument("ecu")
  p.add_argument("item")
  p.add_argument("--kind", choices=("direct", "routine"))
  p.add_argument("--hold", type=float, default=1.0)
  p.add_argument("--poll-interval", type=float, default=0.5)
  p.add_argument("--option-record")
  p.add_argument("--value")
  p.add_argument("--mask")
  p.add_argument("--execute", action="store_true")
  p.add_argument("--json", action="store_true")
  p.set_defaults(func=cmd_utility_run)
  return parser


def _normalize_argv(argv: list[str]) -> list[str]:
  # Preserve the original verb-first surface while allowing the more natural
  # `toyota ecu frc` / `toyota ecu frc data LTA` browsing form. Global profile
  # options may precede the command, so normalize only the command tail.
  prefix: list[str] = []
  index = 0
  while index + 1 < len(argv) and argv[index] in {"--registry", "--profile"}:
    prefix.extend(argv[index:index + 2])
    index += 2
  tail = argv[index:]
  if len(tail) >= 2 and tail[0] == "ecu":
    actions = {"list", "info", "functions", "plugins", "data", "dtcs", "active-tests"}
    if tail[1] not in actions and not tail[1].startswith("-"):
      ref = tail[1]
      if len(tail) >= 3 and tail[2] in actions - {"list", "info"}:
        return [*prefix, "ecu", tail[2], ref, *tail[3:]]
      return [*prefix, "ecu", "info", ref, *tail[2:]]
  return argv


def main(argv: list[str] | None = None) -> int:
  normalized = _normalize_argv(list(sys.argv[1:] if argv is None else argv))
  args = build_parser().parse_args(normalized)
  return int(args.func(args, _profile(args)))


if __name__ == "__main__":
  sys.exit(main())
