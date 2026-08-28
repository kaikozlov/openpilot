"""Generic operation executors for recovered direct (0x2F) and routine (0x31) Active Tests.

Execution is driven exclusively by registry rows the v4 grader marks as
`execution == "executable"` plus every field the wire plan needs: a fully
materialized fixed routine, or a direct test whose exact runtime length is
recovered. The bundled v3 registry marks every Active Test `plan_only` or
`unresolved_static_plan`, so nothing in it resolves to an executable plan —
`resolve_plan` reports why and the run backends refuse to transmit. No runtime
length, control mask, option record, or session requirement is ever inferred from
partial data, and `plan_only`/unresolved rows stay non-executable.

Run backends are explicit-by-default: `execute=False` (the default) performs a
plan-only echo with no transmission. A mutation additionally passes the profile
identity guard and enters the recovered extended session automatically when the
row's `session_requirement` is `extended`. Started operations are always stopped —
including on exception and KeyboardInterrupt — before the error propagates; the
caller owns the `DiagnosticSession` context so session cleanup happens after the
result is returned.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from opendbc.car.uds import CONTROL_PARAMETER_TYPE, ROUTINE_CONTROL_TYPE

from tools.toyota_diag import registry
from tools.toyota_diag.registry import EcuSpec
from tools.toyota_diag.session import DiagnosticSession

EXECUTION_EXECUTABLE = "executable"
SESSION_REQUIREMENT_EXTENDED = "extended"
SESSION_REQUIREMENT_DEFAULT = "default"
SESSION_REQUIREMENT_NONE = "none"
DECLARED_SESSION_REQUIREMENTS = frozenset({SESSION_REQUIREMENT_EXTENDED, SESSION_REQUIREMENT_DEFAULT,
                                           SESSION_REQUIREMENT_NONE})

DIRECT_SERVICE = 0x2F
DIRECT_POSITIVE_SID = 0x6F
ROUTINE_SERVICE = 0x31
ROUTINE_POSITIVE_SID = 0x71
ROUTINE_CONTROL_START = int(ROUTINE_CONTROL_TYPE.START)
ROUTINE_CONTROL_STOP = int(ROUTINE_CONTROL_TYPE.STOP)
ROUTINE_CONTROL_RESULTS = int(ROUTINE_CONTROL_TYPE.REQUEST_RESULTS)
DIRECT_CONTROLS = frozenset(int(control) for control in CONTROL_PARAMETER_TYPE)


class ExecutorError(ValueError):
  """Invalid executor use (wrong kind, missing runtime data, bad lengths)."""


class PlanNotExecutable(ExecutorError):
  """The registry row does not resolve to an executable plan."""

  def __init__(self, plan: TestPlan) -> None:
    self.plan = plan
    details = "; ".join(plan.refusals) if plan.refusals else "plan is not resolved for execution"
    super().__init__(f"{plan.describe()} is not executable: {details}")


@dataclass(frozen=True, kw_only=True)
class TestPlan:
  """Common resolved-plan shape; `executable` is False unless every refusal is empty."""
  ecu: EcuSpec
  test_id: int
  name: str
  kind: str
  session_requirement: str | None = None
  positive_sid: int = 0
  refusals: tuple[str, ...] = ()

  @property
  def executable(self) -> bool:
    return not self.refusals

  def describe(self) -> str:
    return f"{self.ecu.key} 0x{self.test_id:04X} {self.name!r} ({self.kind})"


@dataclass(frozen=True, kw_only=True)
class DirectTestPlan(TestPlan):
  """Recovered 0x2F InputOutputControlByIdentifier plan.

  start/stop prefixes are decomposed as `2F | DID | control | option prefix`; the
  runtime value payload (start) and control-enable mask (stop) are caller-supplied
  explicit bytes of exactly `runtime_length`.
  """
  did: int = 0
  start_control: int = 0
  start_option_prefix: bytes = b""
  stop_control: int = 0
  stop_option_prefix: bytes = b""
  runtime_length: int | None = None


@dataclass(frozen=True, kw_only=True)
class RoutineTestPlan(TestPlan):
  """Recovered 0x31 RoutineControl plan with start/status/stop phases."""
  rid: int = 0
  start_control: int = ROUTINE_CONTROL_START
  start_option_prefix: bytes = b""
  stop_control: int = ROUTINE_CONTROL_STOP
  stop_option_prefix: bytes = b""
  status_control: int | None = None
  status_option_prefix: bytes = b""
  parameterized: bool = False


@dataclass(frozen=True)
class ActiveTestResult:
  plan: TestPlan
  executed: bool
  session_requirement: str | None = None
  start: bytes | None = None
  statuses: tuple[tuple[float, bytes], ...] = ()
  stop: bytes | None = None
  cleanup_errors: tuple[str, ...] = ()


# -- plan resolution -----------------------------------------------------------------------------
def _base_refusals(row: dict[str, Any], kind: str, service: int, positive_sid: int) -> list[str]:
  refusals: list[str] = []
  if row.get("kind") != kind:
    refusals.append(f"kind is {row.get('kind')!r}, expected {kind!r}")
  if row.get("execution") != EXECUTION_EXECUTABLE:
    reason = row.get("reason") or row.get("error") or "no executable runtime authorization"
    refusals.append(f"execution is {row.get('execution')!r}, not {EXECUTION_EXECUTABLE!r} ({reason})")
  if row.get("service") != service:
    refusals.append(f"service is {row.get('service')!r}, expected {service:#04x}")
  if row.get("positive_response") != positive_sid:
    refusals.append(f"positive response SID is {row.get('positive_response')!r}, expected {positive_sid:#04x}")
  if row.get("session_requirement") not in DECLARED_SESSION_REQUIREMENTS:
    declared = ", ".join(sorted(DECLARED_SESSION_REQUIREMENTS))
    refusals.append(f"session_requirement {row.get('session_requirement')!r} is not one of {declared}")
  return refusals


def _decompose_direct_prefix(prefix: bytes, did: int, what: str) -> tuple[int, bytes] | str:
  if len(prefix) < 4 or prefix[0] != DIRECT_SERVICE or int.from_bytes(prefix[1:3], "big") != did:
    return f"{what} {prefix.hex()} is not a resolved {DIRECT_SERVICE:02X} request for DID {did:04X}"
  control = prefix[3]
  if control not in DIRECT_CONTROLS:
    return f"{what} control parameter {control:#04x} is not a known control type"
  return control, prefix[4:]


def _decompose_routine_static(static: bytes, control: int, rid: int, what: str) -> bytes | str:
  if len(static) < 4 or static[0] != ROUTINE_SERVICE or static[1] != control or static[2:4] != rid.to_bytes(2, "big"):
    return f"{what} {static.hex()} is not a resolved {ROUTINE_SERVICE:02X} {control:02X} {rid:04X} request"
  return static[4:]


def resolve_plan(ecu: EcuSpec, row: dict[str, Any]) -> TestPlan:
  """Resolve a registry Active-Test/utility row into a validated plan; never transmits.

  Unresolved or opaque rows resolve with `executable=False` and their refusal
  reasons instead of raising, so plan/list UX can show them.
  """
  kind = row.get("kind")
  name = str(row.get("name") or "")
  try:
    test_id = registry.parse_int(row.get("id", 0), "Active Test id")
  except registry.RegistryError as e:
    return TestPlan(ecu=ecu, test_id=0, name=name, kind=kind or "", refusals=(f"malformed id: {e}",))
  if kind == "direct":
    return _resolve_direct(ecu, test_id, name, row)
  if kind == "routine":
    return _resolve_routine(ecu, test_id, name, row)
  return TestPlan(ecu=ecu, test_id=test_id, name=name, kind=kind or "",
                  refusals=(f"kind is {kind!r}, expected 'direct' or 'routine'",))


def _resolve_direct(ecu: EcuSpec, test_id: int, name: str, row: dict[str, Any]) -> DirectTestPlan:
  refusals = _base_refusals(row, "direct", DIRECT_SERVICE, DIRECT_POSITIVE_SID)
  kwargs: dict[str, Any] = {}
  try:
    did = registry.parse_int(row["did"], "direct did")
    start_prefix = registry.parse_bytes(row["start_prefix"], "direct start_prefix")
    stop_prefix = registry.parse_bytes(row["stop_prefix"], "direct stop_prefix")
    start = _decompose_direct_prefix(start_prefix, did, "start_prefix")
    stop = _decompose_direct_prefix(stop_prefix, did, "stop_prefix")
    if isinstance(start, str) or isinstance(stop, str):
      raise registry.RegistryError(start if isinstance(start, str) else stop)
    kwargs.update(did=did, start_control=start[0], start_option_prefix=start[1],
                  stop_control=stop[0], stop_option_prefix=stop[1])
  except (KeyError, registry.RegistryError) as e:
    refusals.append(f"malformed direct plan: {e}")
    return DirectTestPlan(ecu=ecu, test_id=test_id, name=name, kind="direct",
                          refusals=tuple(refusals))
  runtime_length = row.get("runtime_length")
  if runtime_length is None:
    minimum = row.get("runtime_length_minimum")
    known = f" (only a bit-geometry minimum of {minimum} is known)" if minimum is not None else ""
    refusals.append(f"runtime payload length not definitively recovered{known}")
  else:
    try:
      length = registry.parse_int(runtime_length, "direct runtime_length")
      if length <= 0:
        raise registry.RegistryError(f"direct runtime_length must be positive: {length}")
      kwargs["runtime_length"] = length
    except registry.RegistryError as e:
      refusals.append(f"malformed direct plan: {e}")
  return DirectTestPlan(ecu=ecu, test_id=test_id, name=name, kind="direct",
                        session_requirement=row.get("session_requirement"),
                        positive_sid=DIRECT_POSITIVE_SID, refusals=tuple(refusals), **kwargs)


def _resolve_routine(ecu: EcuSpec, test_id: int, name: str, row: dict[str, Any]) -> RoutineTestPlan:
  refusals = _base_refusals(row, "routine", ROUTINE_SERVICE, ROUTINE_POSITIVE_SID)
  kwargs: dict[str, Any] = {}
  try:
    rid = registry.parse_int(row["routine_id"], "routine routine_id")
    start_option = _decompose_routine_static(registry.parse_bytes(row["start_static"], "routine start_static"),
                                             ROUTINE_CONTROL_START, rid, "start_static")
    stop_option = _decompose_routine_static(registry.parse_bytes(row["stop_static"], "routine stop_static"),
                                            ROUTINE_CONTROL_STOP, rid, "stop_static")
    if isinstance(start_option, str) or isinstance(stop_option, str):
      raise registry.RegistryError(start_option if isinstance(start_option, str) else stop_option)
    kwargs.update(rid=rid, start_option_prefix=start_option, stop_option_prefix=stop_option)
    result_static = row.get("result_static")
    if result_static is not None:
      status_option = _decompose_routine_static(registry.parse_bytes(result_static, "routine result_static"),
                                                ROUTINE_CONTROL_RESULTS, rid, "result_static")
      if isinstance(status_option, str):
        raise registry.RegistryError(status_option)
      kwargs.update(status_control=ROUTINE_CONTROL_RESULTS, status_option_prefix=status_option)
  except (KeyError, registry.RegistryError) as e:
    refusals.append(f"malformed routine plan: {e}")
  return RoutineTestPlan(ecu=ecu, test_id=test_id, name=name, kind="routine",
                         session_requirement=row.get("session_requirement"),
                         positive_sid=ROUTINE_POSITIVE_SID, parameterized=not bool(row.get("fixed_request")),
                         refusals=tuple(refusals), **kwargs)


# -- hold/keepalive loop -------------------------------------------------------------------------------------------
def _hold(session: DiagnosticSession, *, hold_s: float, status_fn: Callable[[], bytes] | None,
          poll_interval_s: float | None, sleep: Callable[[float], None],
          clock: Callable[[], float]) -> tuple[tuple[float, bytes], ...]:
  """Hold an operation: run recovered keepalive and optional status polls until the deadline."""
  lifecycle = session.lifecycle
  keepalive = lifecycle.keepalive if lifecycle is not None else None
  if keepalive is None and status_fn is None:
    sleep(hold_s)
    return ()
  poll_interval = poll_interval_s if poll_interval_s is not None else 0.0
  now = clock()
  deadline = now + hold_s
  next_poll = now + poll_interval if status_fn is not None else float("inf")
  next_keepalive = now + keepalive.interval_s if keepalive is not None else float("inf")
  samples: list[tuple[float, bytes]] = []
  while True:
    now = clock()
    if now >= deadline:
      return tuple(samples)
    if status_fn is not None and now >= next_poll:
      samples.append((now, status_fn()))
      next_poll = now + poll_interval
      continue
    if keepalive is not None and now >= next_keepalive:
      session.keepalive()
      next_keepalive = now + keepalive.interval_s
      continue
    step = deadline - now
    if status_fn is not None:
      step = min(step, max(next_poll - now, 0.0))
    if keepalive is not None:
      step = min(step, max(next_keepalive - now, 0.0))
    sleep(step)


# -- run backends ----------------------------------------------------------------------------------------------------
def _prepare(session: DiagnosticSession, plan: TestPlan, *, execute: bool,
             echo: Callable[[str], None]) -> str | None:
  """Guard identity and enter the recovered extended session when the row requires it.

  Without an explicit execute acknowledgement this performs zero transmissions,
  including the identity guard; the caller gets a plan-only result instead.

  """
  if not execute:
    return plan.session_requirement
  if not plan.executable:
    raise PlanNotExecutable(plan)
  session.guard(echo=echo)
  if plan.session_requirement == SESSION_REQUIREMENT_EXTENDED:
    session.enter_extended(acknowledge=True)
  return plan.session_requirement


def _routine_stop(client, plan: RoutineTestPlan) -> bytes:
  return client.routine_control(ROUTINE_CONTROL_TYPE(plan.stop_control), plan.rid, plan.stop_option_prefix)


def run_direct_test(session: DiagnosticSession, plan: DirectTestPlan, *, hold_s: float,
                    value_payload: bytes = b"", control_enable_mask: bytes = b"", execute: bool = False,
                    echo: Callable[[str], None] = print, sleep: Callable[[float], None] = time.sleep,
                    clock: Callable[[], float] = time.monotonic) -> ActiveTestResult:
  """Run a recovered 0x2F Active Test: start -> hold (keepalive) -> stop/return control.

  `value_payload` and `control_enable_mask` are explicit caller-supplied runtime
  bytes, each exactly `plan.runtime_length` long; nothing is derived from the
  registry's minimum examples.
  """
  if plan.kind != "direct" or not isinstance(plan, DirectTestPlan):
    raise ExecutorError(f"expected a direct plan, got kind {plan.kind!r}")
  if hold_s <= 0:
    raise ExecutorError("hold_s must be positive")
  if execute:
    if plan.runtime_length is None:
      raise PlanNotExecutable(plan)
    if len(value_payload) != plan.runtime_length:
      raise ExecutorError(f"value_payload must be exactly {plan.runtime_length} byte(s), got {len(value_payload)}")
    if len(control_enable_mask) != plan.runtime_length:
      raise ExecutorError(f"control_enable_mask must be exactly {plan.runtime_length} byte(s), got {len(control_enable_mask)}")

  session_requirement = _prepare(session, plan, execute=execute, echo=echo)
  if not execute:
    return ActiveTestResult(plan=plan, executed=False, session_requirement=session_requirement)

  client = session.client()

  def start_control() -> bytes:
    return client.input_output_control_by_identifier(
      plan.did, CONTROL_PARAMETER_TYPE(plan.start_control), plan.start_option_prefix + value_payload, b"")

  def stop_control() -> bytes:
    return client.input_output_control_by_identifier(
      plan.did, CONTROL_PARAMETER_TYPE(plan.stop_control), plan.stop_option_prefix, control_enable_mask)

  started = False
  cleanup_errors: list[str] = []
  try:
    start = start_control()
    started = True
    statuses = _hold(session, hold_s=hold_s, status_fn=None, poll_interval_s=None, sleep=sleep, clock=clock)
    stop = stop_control()
  except BaseException:
    if started:
      _best_effort_stop(cleanup_errors, stop_control)
    raise
  return ActiveTestResult(plan=plan, executed=True, session_requirement=session_requirement, start=start,
                          statuses=statuses, stop=stop, cleanup_errors=tuple(cleanup_errors + session.cleanup_errors))


def run_routine_test(session: DiagnosticSession, plan: RoutineTestPlan, *, hold_s: float,
                     option_record: bytes | None = None, execute: bool = False, poll_interval_s: float = 0.5,
                     echo: Callable[[str], None] = print, sleep: Callable[[float], None] = time.sleep,
                     clock: Callable[[], float] = time.monotonic) -> ActiveTestResult:
  """Run a recovered 0x31 Active Test/utility: start -> status polls/keepalive -> stop.

  Parameterized routines (registry `fixed_request` false) require an explicit
  `option_record`; fixed routines refuse one — static bytes alone never authorize
  invented runtime data.
  """
  if plan.kind != "routine" or not isinstance(plan, RoutineTestPlan):
    raise ExecutorError(f"expected a routine plan, got kind {plan.kind!r}")
  if hold_s <= 0:
    raise ExecutorError("hold_s must be positive")
  if plan.parameterized:
    if not option_record:
      raise ExecutorError("registry marks this routine parameterized; explicit option_record bytes are required")
  elif option_record:
    raise ExecutorError("fixed routine takes no runtime option record")

  session_requirement = _prepare(session, plan, execute=execute, echo=echo)
  if not execute:
    return ActiveTestResult(plan=plan, executed=False, session_requirement=session_requirement)

  client = session.client()
  start_option = plan.start_option_prefix + (option_record if plan.parameterized else b"")

  def start_control() -> bytes:
    return client.routine_control(ROUTINE_CONTROL_TYPE(plan.start_control), plan.rid, start_option)

  def emergency_stop() -> None:
    _routine_stop(client, plan)

  started = False
  cleanup_errors: list[str] = []
  try:
    start = start_control()
    started = True
    statuses = _hold(session, hold_s=hold_s, status_fn=_status_poller(client, plan),
                     poll_interval_s=poll_interval_s, sleep=sleep, clock=clock)
    stop = _routine_stop(client, plan)
  except BaseException:
    if started:
      _best_effort_stop(cleanup_errors, emergency_stop)
    raise
  return ActiveTestResult(plan=plan, executed=True, session_requirement=session_requirement, start=start,
                          statuses=statuses, stop=stop, cleanup_errors=tuple(cleanup_errors + session.cleanup_errors))


def _status_poller(client, plan: RoutineTestPlan) -> Callable[[], bytes] | None:
  if plan.status_control is None:
    return None

  def poll() -> bytes:
    return client.routine_control(ROUTINE_CONTROL_TYPE(plan.status_control), plan.rid, plan.status_option_prefix)

  return poll


def _best_effort_stop(errors: list[str], stop: Callable[[], Any]) -> None:
  try:
    stop()
  except BaseException as e:  # guarantee the original failure propagates
    errors.append(f"emergency stop failed: {e!r}")
