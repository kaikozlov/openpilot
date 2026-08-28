"""Techstream-style Utilities backend over the registry catalogs.

Concrete executable utilities are catalog rows (`catalogs.<id>.utilities`) with
the same shape as Active Tests; planning/running reuses the executor backends.
Registry v4 additionally carries top-level recovered generic utility-family
metadata (`utilities.bindings`) for discovery only. Those families are never
silently promoted into executable per-ECU operations.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from tools.toyota_diag import executor
from tools.toyota_diag.executor import ActiveTestResult, DirectTestPlan, RoutineTestPlan, TestPlan
from tools.toyota_diag.registry import EcuSpec, Profile
from tools.toyota_diag.session import DiagnosticSession

PLAN_ONLY_NOTE = "no utility request is sent without an explicit execute acknowledgement"


def list_families(profile: Profile) -> list[dict[str, Any]]:
  """Recovered generic utility/plugin families; metadata-only in registry v4."""
  return profile.utility_bindings()


def plan_family(profile: Profile, query: str) -> dict[str, Any]:
  """Resolve one generic utility family without claiming a concrete ECU operation."""
  return profile.lookup_utility_family(query)


def list_utilities(profile: Profile, ecu: EcuSpec | None = None) -> list[tuple[EcuSpec, list[dict[str, Any]]]]:
  """All utility rows per ECU, in profile order; ECUs without utilities are omitted."""
  targets = [ecu] if ecu is not None else list(profile.ecus)
  return [(spec, rows) for spec in targets if (rows := profile.utilities(spec))]


def plan_utility(profile: Profile, ecu: EcuSpec | str | int, query: str, *, kind: str | None = None) -> TestPlan:
  """Resolve one utility row (numeric id or name query) into an executor plan."""
  spec = ecu if isinstance(ecu, EcuSpec) else profile.lookup_ecu(ecu)
  row = profile.lookup_utility(spec, query, kind=kind)
  return executor.resolve_plan(spec, row)


def run_utility(session: DiagnosticSession, plan: TestPlan, *, hold_s: float, execute: bool = False,
                option_record: bytes | None = None, value_payload: bytes = b"", control_enable_mask: bytes = b"",
                poll_interval_s: float = 0.5, echo: Callable[[str], None] = print) -> ActiveTestResult:
  """Run a planned utility through the matching executor backend."""
  if isinstance(plan, RoutineTestPlan):
    return executor.run_routine_test(session, plan, hold_s=hold_s, option_record=option_record, execute=execute,
                                     poll_interval_s=poll_interval_s, echo=echo)
  if isinstance(plan, DirectTestPlan):
    return executor.run_direct_test(session, plan, hold_s=hold_s, value_payload=value_payload,
                                    control_enable_mask=control_enable_mask, execute=execute, echo=echo)
  raise executor.ExecutorError(f"expected a routine or direct utility plan, got kind {plan.kind!r}")
