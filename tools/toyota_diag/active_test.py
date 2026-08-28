"""Read-only rendering for GTS+-derived Active-Test plans.

There is intentionally no transport import or execution function in this module.
"""
from __future__ import annotations

from typing import Any

from tools.toyota_diag.registry import EcuSpec, Profile

PLAN_ONLY_BANNER = "PLAN ONLY - no Active Test request is sent."


def render_list(profile: Profile, ecu: EcuSpec | None = None) -> str:
  ecus = [ecu] if ecu is not None else [item for item in profile.ecus if profile.active_tests(item)]
  lines = [PLAN_ONLY_BANNER]
  for spec in ecus:
    tests = profile.active_tests(spec)
    if not tests:
      continue
    lines.append(f"\n{spec.key} ({spec.name}) - {len(tests)} candidate(s)")
    for test in tests:
      state = "resolved" if test.get("execution") == "plan_only" else "unresolved"
      lines.append(f"  0x{int(test['id']):04X}  {test.get('kind','?'):<7} {state:<10} {test.get('name') or ''}")
  if len(lines) == 1:
    lines.append("no Active Tests in selected catalog")
  return "\n".join(lines)


def render_plan(ecu: EcuSpec, test: dict[str, Any]) -> str:
  lines = [
    PLAN_ONLY_BANNER,
    f"ECU: {ecu.key} ({ecu.name})",
    f"Active Test: 0x{int(test['id']):04X} {test.get('name') or ''}",
    f"kind: {test.get('kind')}",
    f"resolution: {test.get('execution')}",
  ]
  if test.get("execution") != "plan_only":
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
      lines.append("parameterized: static bytes are not authorization to invent runtime value/button data")
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
  return "\n".join(lines)
