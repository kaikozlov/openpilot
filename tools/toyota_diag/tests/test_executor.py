import unittest

from opendbc.car.uds import MessageTimeoutError, NegativeResponseError

from tools.toyota_diag import registry
from tools.toyota_diag.executor import (DirectTestPlan, ExecutorError, PlanNotExecutable, RoutineTestPlan,
                                        resolve_plan, run_direct_test, run_routine_test, runtime_refusals)
from tools.toyota_diag.session import DiagnosticSession
from tools.toyota_diag.tests import support

ADDR = support.SYNTH_ECU_ADDRESS


def current_p5(keepalive=None):
  lifecycle = {
    "generation": "current-p5", "default_session": 1, "extended_session": 3,
    "enter_sequence": ["1001", "1003"], "return_default": "1001",
  }
  if keepalive is not None:
    lifecycle["keepalive"] = keepalive
  return lifecycle


def executable_routine(**overrides):
  row = {
    "id": 0x2001, "name": "Check Fuel Pressure", "kind": "routine", "execution": "executable",
    "service": 0x31, "positive_response": 0x71, "session_requirement": "default", "fixed_request": True,
    "routine_id": 0x1105, "start_static": "31011105", "stop_static": "31021105", "result_static": "31031105",
  }
  row.update(overrides)
  return row


def executable_direct(**overrides):
  row = {
    "id": 0x1001, "name": "Activate Valve", "kind": "direct", "execution": "executable",
    "service": 0x2F, "positive_response": 0x6F, "session_requirement": "extended",
    "did": 0x2801, "start_prefix": "2f280103", "stop_prefix": "2f280100", "runtime_length": 2,
  }
  row.update(overrides)
  return row


def routine_scripts(scripted, rid=0x1105, addr=ADDR):
  scripted.routine.update({
    (addr, 1, rid): b"\x00", (addr, 2, rid): b"\x00", (addr, 3, rid): b"\x01",
  })


def routine_controls(scripted):
  return [call[2] for call in scripted.calls if call[1] == "routine"]


def session_calls(scripted):
  return [call[2] for call in scripted.calls if call[1] == "session"]


class TestPlanResolution(unittest.TestCase):
  def test_bundled_v4_runtime_grades_are_stricter_than_static_geometry(self):
    profile = registry.load_registry()

    frc_row = profile.lookup_active_test("frc", "0xA429")
    frc_plan = resolve_plan(profile.lookup_ecu("frc"), frc_row)
    self.assertTrue(frc_plan.executable)
    self.assertEqual(runtime_refusals(profile, frc_plan), ())

    engine_row = next(row for row in profile.active_tests("engine") if row.get("execution") == "executable")
    engine_plan = resolve_plan(profile.lookup_ecu("engine"), engine_row)
    self.assertTrue(engine_plan.executable)  # static request geometry is complete
    self.assertIn("not wire-proven for ECU category 372", " ".join(runtime_refusals(profile, engine_plan)))

    brake_row = profile.lookup_active_test("brake", "42001")
    brake_plan = resolve_plan(profile.lookup_ecu("brake"), brake_row)
    self.assertFalse(brake_plan.executable)
    self.assertIn("placeholder 0xFFFF", " ".join(brake_plan.refusals))

  def test_legacy_v3_row_stays_plan_only_without_runtime_authorization(self):
    profile = support.load_profile(None, active_tests=[executable_routine(execution="plan_only")])
    row = profile.lookup_active_test("ecu", "0x2001")
    plan = resolve_plan(profile.lookup_ecu("ecu"), row)
    self.assertFalse(plan.executable)
    self.assertIn("execution is 'plan_only'", " ".join(plan.refusals))

  def test_unresolved_and_partially_recovered_rows_refuse(self):
    ecu = support.synthetic_ecu(support.load_profile(None))
    unresolved = resolve_plan(ecu, executable_routine(execution="unresolved_static_plan", reason="no DLL"))
    self.assertFalse(unresolved.executable)
    self.assertIn("no DLL", " ".join(unresolved.refusals))

    minimum_only = resolve_plan(ecu, executable_direct(runtime_length=None, runtime_length_minimum=2))
    self.assertFalse(minimum_only.executable)
    joined = " ".join(minimum_only.refusals)
    self.assertIn("runtime payload length not definitively recovered", joined)
    self.assertIn("minimum of 2", joined)

    no_session = resolve_plan(ecu, executable_routine(session_requirement=None))
    self.assertFalse(no_session.executable)
    self.assertIn("session_requirement None", " ".join(no_session.refusals))

    bad_service = resolve_plan(ecu, executable_routine(service=0x2F))
    self.assertFalse(bad_service.executable)

    opaque_static = resolve_plan(ecu, executable_routine(stop_static="2E021105"))
    self.assertFalse(opaque_static.executable)
    self.assertIn("malformed routine plan", " ".join(opaque_static.refusals))

  def test_executable_rows_resolve_with_decomposed_wire_plans(self):
    ecu = support.synthetic_ecu(support.load_profile(None))
    routine = resolve_plan(ecu, executable_routine())
    self.assertIsInstance(routine, RoutineTestPlan)
    self.assertTrue(routine.executable)
    self.assertEqual((routine.rid, routine.start_control, routine.stop_control, routine.status_control),
                     (0x1105, 1, 2, 3))
    self.assertFalse(routine.parameterized)

    direct = resolve_plan(ecu, executable_direct())
    self.assertIsInstance(direct, DirectTestPlan)
    self.assertTrue(direct.executable)
    self.assertEqual((direct.did, direct.start_control, direct.stop_control, direct.runtime_length),
                     (0x2801, 3, 0, 2))

    parameterized = resolve_plan(ecu, executable_routine(fixed_request=False))
    self.assertTrue(parameterized.parameterized)
    self.assertTrue(parameterized.executable)


class TestRoutineExecution(unittest.TestCase):
  def setUp(self):
    self.scripted = support.ScriptedUds()
    support.guard_pass(self.scripted)

  def run_with(self, row, *, session_control=None, **kwargs):
    profile = support.load_profile(None, session_control=session_control)
    ecu = support.synthetic_ecu(profile)
    plan = resolve_plan(ecu, row)
    assert isinstance(plan, RoutineTestPlan)
    session = DiagnosticSession(profile, ecu, client_factory=self.scripted.factory, operation_row=row)
    kwargs.setdefault("hold_s", 0.02)
    kwargs.setdefault("poll_interval_s", 0.005)
    return run_routine_test(session, plan, echo=lambda text: None, sleep=lambda seconds: None, **kwargs)

  def test_fixed_routine_runs_start_status_stop_in_order(self):
    routine_scripts(self.scripted)
    result = self.run_with(executable_routine(), execute=True)
    self.assertTrue(result.executed)
    self.assertEqual(result.start, b"\x00")
    self.assertEqual(result.stop, b"\x00")
    self.assertTrue(result.statuses)
    controls = routine_controls(self.scripted)
    self.assertEqual(controls[0], 1)          # start first
    self.assertEqual(controls[-1], 2)         # stop last
    self.assertEqual(set(controls[1:-1]), {3})  # only status polls in between
    self.assertGreaterEqual(len(controls), 3)
    self.assertEqual(self.scripted.calls[0], (ADDR, "read_did", 0xF181))  # guard before everything

  def test_execute_acknowledgement_gates_all_transmission_including_guard(self):
    routine_scripts(self.scripted)
    result = self.run_with(executable_routine(), execute=False)
    self.assertFalse(result.executed)
    self.assertEqual(result.session_requirement, "default")
    self.assertEqual(self.scripted.calls, [])  # not even the identity guard read

  def test_identity_guard_precedes_every_mutation(self):
    routine_scripts(self.scripted)
    self.scripted.did[ADDR] = {0xF181: b"NOT-MY-CAR"}
    with self.assertRaises(SystemExit):
      self.run_with(executable_routine(), execute=True)
    self.assertEqual([call[1] for call in self.scripted.calls], ["read_did"])

  def test_extended_requirement_full_lifecycle_order(self):
    routine_scripts(self.scripted)
    lifecycle = current_p5(keepalive={"kind": "session_did_poll", "interval_s": 30.0})
    self.scripted.did[ADDR] = {0xF181: support.EXPECTED_EPS_F181, 0xF186: b"\x01"}  # poll reports default
    profile = support.load_profile(None, session_control=lifecycle)
    with DiagnosticSession(profile, support.synthetic_ecu(profile),
                           client_factory=self.scripted.factory) as session:
      plan = resolve_plan(session.ecu, executable_routine(session_requirement="extended"))
      assert isinstance(plan, RoutineTestPlan)
      result = run_routine_test(session, plan, hold_s=0.02, poll_interval_s=0.005, execute=True,
                                echo=lambda text: None, sleep=lambda seconds: None)
    self.assertEqual(result.session_requirement, "extended")
    calls = list(self.scripted.calls)
    for expected in [
      (ADDR, "read_did", 0xF181),   # identity guard
      (ADDR, "read_did", 0xF186),   # recovered session-state poll
      (ADDR, "session", 1),         # D1
      (ADDR, "session", 3),         # D2
      (ADDR, "routine", 1, 0x1105, b""),
    ]:
      index = calls.index(expected)
      calls = calls[index + 1:]
    controls = routine_controls(self.scripted)
    self.assertEqual((controls[0], controls[-1]), (1, 2))
    self.assertEqual(self.scripted.calls[-1], (ADDR, "session", 1))  # D1 cleanup after stop

  @staticmethod
  def profile_for(lifecycle):
    return support.load_profile(None, session_control=lifecycle)

  def test_extended_requirement_without_lifecycle_fails_closed_before_start(self):
    routine_scripts(self.scripted)
    with self.assertRaises(PlanNotExecutable):
      self.run_with(executable_routine(session_requirement="extended"), execute=True)
    self.assertEqual(self.scripted.calls, [])  # lifecycle refusal happens before even the identity-guard read

  def test_exception_during_hold_still_stops_the_routine(self):
    self.scripted.routine[(ADDR, 1, 0x1105)] = b"\x00"
    self.scripted.routine[(ADDR, 3, 0x1105)] = NegativeResponseError("conditions not correct", 0x31, 0x22)
    self.scripted.routine[(ADDR, 2, 0x1105)] = b"\x00"
    with self.assertRaises(NegativeResponseError):
      self.run_with(executable_routine(), execute=True)
    controls = routine_controls(self.scripted)
    self.assertEqual((controls[0], controls[-1]), (1, 2))

  def test_keyboard_interrupt_still_stops_the_routine(self):
    routine_scripts(self.scripted)

    def interrupt(seconds):
      raise KeyboardInterrupt

    profile = support.load_profile(None)
    ecu = support.synthetic_ecu(profile)
    plan = resolve_plan(ecu, executable_routine())
    assert isinstance(plan, RoutineTestPlan)
    session = DiagnosticSession(profile, ecu, client_factory=self.scripted.factory)
    with self.assertRaises(KeyboardInterrupt):
      run_routine_test(session, plan, hold_s=5.0, execute=True, poll_interval_s=0.005,
                       echo=lambda text: None, sleep=interrupt)
    self.assertEqual(routine_controls(self.scripted), [1, 2])

  def test_emergency_stop_failure_is_recorded_not_swallowed(self):
    self.scripted.routine[(ADDR, 1, 0x1105)] = b"\x00"
    self.scripted.routine[(ADDR, 3, 0x1105)] = MessageTimeoutError()
    self.scripted.routine[(ADDR, 2, 0x1105)] = MessageTimeoutError()

    def no_sleep(seconds):
      raise KeyboardInterrupt

    profile = support.load_profile(None)
    ecu = support.synthetic_ecu(profile)
    plan = resolve_plan(ecu, executable_routine())
    assert isinstance(plan, RoutineTestPlan)
    session = DiagnosticSession(profile, ecu, client_factory=self.scripted.factory)
    with self.assertRaises(KeyboardInterrupt) as caught:
      run_routine_test(session, plan, hold_s=5.0, execute=True, echo=lambda text: None, sleep=no_sleep)
    self.assertEqual(routine_controls(self.scripted), [1, 2])  # stop attempted even though it timed out
    self.assertIn("emergency stop failed", " ".join(caught.exception.toyota_cleanup_errors))

  def test_parameterized_routine_requires_explicit_option_record(self):
    routine_scripts(self.scripted)
    dry = self.run_with(executable_routine(fixed_request=False), execute=False)
    self.assertFalse(dry.executed)
    self.assertEqual(self.scripted.calls, [])  # dry-run never validates runtime payload by touching the vehicle

    with self.assertRaises(ExecutorError):
      self.run_with(executable_routine(fixed_request=False), execute=True)
    self.assertEqual(self.scripted.calls, [])  # refused before any read or transmit

    result = self.run_with(executable_routine(fixed_request=False), execute=True, option_record=b"\x01\x02")
    start_call = next(call for call in self.scripted.calls if call[1] == "routine" and call[2] == 1)
    self.assertEqual(start_call[4], b"\x01\x02")
    self.assertTrue(result.executed)

  def test_fixed_routine_refuses_runtime_option_record(self):
    routine_scripts(self.scripted)
    with self.assertRaises(ExecutorError):
      self.run_with(executable_routine(), execute=True, option_record=b"\x01")
    self.assertEqual(self.scripted.calls, [])

  def test_plan_only_row_never_transmits_even_with_ack(self):
    row = executable_routine(execution="plan_only")
    profile = support.load_profile(None)
    ecu = support.synthetic_ecu(profile)
    plan = resolve_plan(ecu, row)
    assert isinstance(plan, RoutineTestPlan)
    session = DiagnosticSession(profile, ecu, client_factory=self.scripted.factory)
    with self.assertRaises(PlanNotExecutable):
      run_routine_test(session, plan, hold_s=0.02, execute=True, echo=lambda text: None)
    result = run_routine_test(session, plan, hold_s=0.02, echo=lambda text: None)
    self.assertFalse(result.executed)
    self.assertEqual(self.scripted.calls, [])

  def test_keepalive_runs_during_hold(self):
    routine_scripts(self.scripted)
    self.scripted.tester[ADDR] = None
    self.run_with(executable_routine(), session_control=current_p5(
      keepalive={"kind": "tester_present", "interval_s": 0.005}), execute=True)
    self.assertIn((ADDR, "tester_present"), self.scripted.calls)


class TestDirectExecution(unittest.TestCase):
  def setUp(self):
    self.scripted = support.ScriptedUds()
    support.guard_pass(self.scripted)
    self.scripted.io_control.update({
      (ADDR, 0x2801, 3): b"\x01", (ADDR, 0x2801, 0): b"\x00",
    })

  def run_with(self, row, *, session_control=None, **kwargs):
    profile = support.load_profile(None, session_control=session_control)
    ecu = support.synthetic_ecu(profile)
    plan = resolve_plan(ecu, row)
    assert isinstance(plan, DirectTestPlan)
    kwargs.setdefault("hold_s", 0.01)
    with DiagnosticSession(profile, ecu, client_factory=self.scripted.factory, operation_row=row) as session:
      return run_direct_test(session, plan, echo=lambda text: None, sleep=lambda seconds: None, **kwargs)

  def test_direct_lifecycle_and_wire_shape(self):
    result = self.run_with(executable_direct(), session_control=current_p5(), execute=True,
                           value_payload=b"\x00\x01", control_enable_mask=b"\x00\x01")
    self.assertTrue(result.executed)
    calls = list(self.scripted.calls)
    for expected in [
      (ADDR, "read_did", 0xF181),                        # guard
      (ADDR, "session", 1), (ADDR, "session", 3),        # D1/D2 SendProc (no poll declared)
      (ADDR, "io_control", 0x2801, 3, b"\x00\x01", b""),  # start with explicit payload
      (ADDR, "io_control", 0x2801, 0, b"", b"\x00\x01"),  # stop with explicit mask
      (ADDR, "session", 1),                              # D1 cleanup after stop
    ]:
      index = calls.index(expected)
      calls = calls[index + 1:]
    self.assertEqual(self.scripted.calls[-1], (ADDR, "session", 1))

  def test_payload_and_mask_lengths_are_enforced_before_any_transmission(self):
    for payload, mask in ((b"\x01", b"\x00\x01"), (b"\x00\x01", b"\x01"), (b"", b"")):
      with self.assertRaises(ExecutorError):
        self.run_with(executable_direct(), session_control=current_p5(), execute=True,
                      value_payload=payload, control_enable_mask=mask)
    self.assertEqual(self.scripted.calls, [])

  def test_direct_without_recovered_runtime_length_never_executes(self):
    row = executable_direct(runtime_length=None, runtime_length_minimum=2)
    with self.assertRaises(PlanNotExecutable):
      self.run_with(row, session_control=current_p5(), execute=True,
                    value_payload=b"\x00\x01", control_enable_mask=b"\x00\x01")
    self.assertEqual(self.scripted.calls, [])

  def test_exception_during_hold_stops_control(self):
    self.scripted.io_control[(ADDR, 0x2801, 0)] = MessageTimeoutError()

    def stop_fails(seconds):
      raise KeyboardInterrupt

    profile = support.load_profile(None, session_control=current_p5())
    ecu = support.synthetic_ecu(profile)
    row = executable_direct()
    plan = resolve_plan(ecu, row)
    assert isinstance(plan, DirectTestPlan)
    session = DiagnosticSession(profile, ecu, client_factory=self.scripted.factory, operation_row=row)
    with self.assertRaises(KeyboardInterrupt):
      run_direct_test(session, plan, hold_s=5.0, execute=True, value_payload=b"\x00\x01",
                      control_enable_mask=b"\x00\x01", echo=lambda text: None, sleep=stop_fails)
    controls = [call[3] for call in self.scripted.calls if call[1] == "io_control"]
    self.assertEqual(controls, [3, 0])  # start then emergency stop


if __name__ == "__main__":
  unittest.main()
