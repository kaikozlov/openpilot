"""Rendering helpers for GTS+-derived Active-Test plans.

Rendering never transmits. Runtime execution lives in :mod:`executor` and requires
an explicit acknowledgement plus a registry row graded ``execution=executable``.
"""
from __future__ import annotations

from typing import Any

from tools.toyota_diag import executor
from tools.toyota_diag.registry import EcuSpec, Profile

PLAN_VIEW_BANNER = "PLAN VIEW - no Active Test request is sent."


def _grade(profile: Profile, ecu: EcuSpec, row: dict[str, Any]) -> str:
  plan = executor.resolve_plan(ecu, row)
  if not executor.runtime_refusals(profile, plan):
    return "executable"
  execution = str(row.get("execution") or "unresolved")
  if execution == "executable":
    return "blocked"
  if execution == "plan_only":
    return "plan-only"
  return "unresolved"


def describe(profile: Profile, ecu: EcuSpec, row: dict[str, Any]) -> dict[str, Any]:
  """Machine-readable zero-transmit view of one recovered Active Test."""
  plan = executor.resolve_plan(ecu, row)
  refusals = executor.runtime_refusals(profile, plan)
  grade = _grade(profile, ecu, row)
  return {
    "ecu": {"key": ecu.key, "name": ecu.name, "address": ecu.address, "category_id": ecu.category_id},
    "id": int(row.get("id", 0)),
    "name": str(row.get("name") or ""),
    "kind": str(row.get("kind") or ""),
    "registry_execution": str(row.get("execution") or "unresolved"),
    "runtime_execution": grade,
    "runtime_executable": not refusals,
    "runtime_refusals": list(refusals),
    "session_requirement": row.get("session_requirement"),
    "wire_plan": dict(row),
  }


def list_document(profile: Profile, ecu: EcuSpec | None = None) -> dict[str, Any]:
  targets = [ecu] if ecu is not None else [item for item in profile.ecus if profile.active_tests(item)]
  rows = [describe(profile, spec, test) for spec in targets for test in profile.active_tests(spec)]
  return {"profile": profile.name, "vehicle": profile.vehicle, "active_tests": rows}


def render_list(profile: Profile, ecu: EcuSpec | None = None) -> str:
  ecus = [ecu] if ecu is not None else [item for item in profile.ecus if profile.active_tests(item)]
  lines = [PLAN_VIEW_BANNER]
  for spec in ecus:
    tests = profile.active_tests(spec)
    if not tests:
      continue
    lines.append(f"\n{spec.key} ({spec.name}) - {len(tests)} candidate(s)")
    for test in tests:
      lines.append(
        f"  0x{int(test['id']):04X}  {test.get('kind','?'):<7} {_grade(profile, spec, test):<10} {test.get('name') or ''}")
  if len(lines) == 1:
    lines.append("no Active Tests in selected catalog")
  return "\n".join(lines)


def render_plan(profile: Profile, ecu: EcuSpec, test: dict[str, Any]) -> str:
  execution = str(test.get("execution") or "unresolved_static_plan")
  plan = executor.resolve_plan(ecu, test)
  runtime_refusals = executor.runtime_refusals(profile, plan)
  lines = [
    PLAN_VIEW_BANNER,
    f"ECU: {ecu.key} ({ecu.name})",
    f"Active Test: 0x{int(test['id']):04X} {test.get('name') or ''}",
    f"kind: {test.get('kind')}",
    f"resolution: {execution}",
  ]
  if test.get("session_requirement"):
    lines.append(f"session: {test['session_requirement']}")
  if execution == "unresolved_static_plan":
    lines.append(f"reason: {test.get('reason') or test.get('error') or 'static plan unresolved'}")
    return "\n".join(lines)

  if test.get("kind") == "routine":
    lines.extend([
      f"RID: 0x{int(test['routine_id']):04X}",
      f"start_static:  {test.get('start_static')}",
      f"stop_static:   {test.get('stop_static')}",
      f"result_static: {test.get('result_static')}",
      f"positive SID:  0x{int(test['positive_response']):02X}",
      f"fixed request: {bool(test.get('fixed_request'))}",
    ])
    if not test.get("fixed_request"):
      lines.append("parameterized: runtime value/button data remains explicit and is never invented")
  elif test.get("kind") == "direct":
    lines.extend([
      f"DID: 0x{int(test['did']):04X}",
      f"bits: {test.get('bit_start')}..{test.get('bit_end')}",
      f"start prefix: {test.get('start_prefix')} || N-byte value payload",
      f"stop prefix:  {test.get('stop_prefix')} || N-byte control-enable mask",
      f"positive SID: 0x{int(test['positive_response']):02X}",
      f"runtime N minimum from bit geometry: {test.get('runtime_length_minimum')}",
    ])
    examples = test.get("minimum_examples")
    if examples:
      lines.append(f"minimum examples only: {examples.get('raw_0')} / {examples.get('raw_1')} / {examples.get('return_control')}")
  if not runtime_refusals:
    lines.append("runtime: executable; transmission still requires explicit --execute and the vehicle identity guard")
  elif execution == "executable":
    lines.append("runtime: blocked despite complete static geometry")
    lines.extend(f"  refusal: {reason}" for reason in runtime_refusals)
  else:
    lines.append("runtime: plan-only; unresolved runtime data prevents execution")
    lines.extend(f"  refusal: {reason}" for reason in runtime_refusals)
  return "\n".join(lines)
