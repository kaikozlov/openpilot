import unittest

from tools.toyota_diag import registry, utility
from tools.toyota_diag.executor import ExecutorError, PlanNotExecutable, RoutineTestPlan
from tools.toyota_diag.session import DiagnosticSession
from tools.toyota_diag.tests import support

ADDR = support.SYNTH_ECU_ADDRESS


def executable_utility(**overrides):
  row = {
    "id": 0x3001, "name": "Fuel Pressure Check", "kind": "routine", "execution": "executable",
    "service": 0x31, "positive_response": 0x71, "session_requirement": "none", "fixed_request": True,
    "routine_id": 0x2002, "start_static": "31012002", "stop_static": "31022002", "result_static": "31032002",
  }
  row.update(overrides)
  return row


def executable_direct_utility(**overrides):
  row = {
    "id": 0x3003, "name": "Valve Utility", "kind": "direct", "execution": "executable",
    "service": 0x2F, "positive_response": 0x6F, "session_requirement": "none",
    "did": 0x2801, "start_prefix": "2f280103", "stop_prefix": "2f280100", "runtime_length": 2,
  }
  row.update(overrides)
  return row


class TestBundledRegistry(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.profile = registry.load_registry()

  def test_bundled_v4_exposes_generic_families_but_no_concrete_utilities(self):
    self.assertIsNotNone(self.profile.session_control)
    self.assertEqual(utility.list_utilities(self.profile), [])
    self.assertEqual(self.profile.utilities("frc"), [])
    families = utility.list_families(self.profile)
    self.assertEqual(len(families), 10)
    self.assertEqual(utility.plan_family(self.profile, "0xD4")["semantic_kind"], "single_routine_active_test")
    with self.assertRaises(registry.RegistryError):
      self.profile.lookup_utility("frc", "0x3001")


class TestUtilityBackend(unittest.TestCase):
  def setUp(self):
    self.scripted = support.ScriptedUds()
    support.guard_pass(self.scripted)
    self.scripted.routine.update({
      (ADDR, 1, 0x2002): b"\x00", (ADDR, 2, 0x2002): b"\x00", (ADDR, 3, 0x2002): b"\x02",
    })
    self.profile = support.load_profile(None, utilities=[
      executable_utility(),
      executable_utility(id=0x3002, name="Plan Only Utility", kind="direct", execution="plan_only",
                         service=0x2F, positive_response=0x6F, did=0x2801,
                         start_prefix="2f280103", stop_prefix="2f280100"),
      executable_direct_utility(),
    ])
    self.ecu = support.synthetic_ecu(self.profile)

  def test_list_utilities_reports_rows_per_ecu(self):
    listed = utility.list_utilities(self.profile)
    self.assertEqual([(spec.key, len(rows)) for spec, rows in listed], [(self.ecu.key, 3)])
    self.assertEqual(utility.list_utilities(self.profile, self.ecu)[0][1][0]["name"], "Fuel Pressure Check")

  def test_plan_utility_resolves_by_id_and_name(self):
    by_id = utility.plan_utility(self.profile, self.ecu, "0x3001")
    by_name = utility.plan_utility(self.profile, self.ecu, "Fuel Pressure Check")
    self.assertIsInstance(by_id, RoutineTestPlan)
    self.assertTrue(by_id.executable)
    self.assertEqual(by_id.rid, 0x2002)
    self.assertEqual(by_name.test_id, 0x3001)

  def test_run_utility_executes_executable_routine_without_session_transitions(self):
    plan = utility.plan_utility(self.profile, self.ecu, "0x3001")
    with DiagnosticSession(self.profile, self.ecu, client_factory=self.scripted.factory) as session:
      result = utility.run_utility(session, plan, hold_s=0.01, execute=True, echo=lambda text: None)
    self.assertTrue(result.executed)
    controls = [call[2] for call in self.scripted.calls if call[1] == "routine"]
    self.assertEqual((controls[0], controls[-1]), (1, 2))
    self.assertEqual([call for call in self.scripted.calls if call[1] == "session"], [])  # requirement "none"

  def test_run_utility_plan_only_without_ack_transmits_nothing(self):
    plan = utility.plan_utility(self.profile, self.ecu, "0x3001")
    with DiagnosticSession(self.profile, self.ecu, client_factory=self.scripted.factory) as session:
      result = utility.run_utility(session, plan, hold_s=0.01, echo=lambda text: None)
    self.assertFalse(result.executed)
    self.assertEqual(self.scripted.calls, [])

  def test_plan_only_utility_fails_closed_on_ack(self):
    plan = utility.plan_utility(self.profile, self.ecu, "0x3002")
    self.assertFalse(plan.executable)
    with DiagnosticSession(self.profile, self.ecu, client_factory=self.scripted.factory) as session:
      with self.assertRaises(PlanNotExecutable):
        utility.run_utility(session, plan, hold_s=0.01, execute=True, echo=lambda text: None)
    self.assertEqual(self.scripted.calls, [])

  def test_direct_utility_requires_explicit_runtime_bytes(self):
    plan = utility.plan_utility(self.profile, self.ecu, "0x3003")
    with DiagnosticSession(self.profile, self.ecu, client_factory=self.scripted.factory) as session:
      with self.assertRaises(ExecutorError):
        utility.run_utility(session, plan, hold_s=0.01, execute=True, echo=lambda text: None)
    self.assertEqual(self.scripted.calls, [])  # refused before any read or transmit

  def test_unknown_kind_query_fails_closed(self):
    with self.assertRaises(registry.RegistryError):
      utility.plan_utility(self.profile, self.ecu, "no such utility")


if __name__ == "__main__":
  unittest.main()
