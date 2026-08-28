import unittest

from opendbc.car.uds import get_dtc_status_names

from tools.toyota_diag import registry
from tools.toyota_diag.tests import support


class TestRegistry(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.profile = registry.load_registry()

  def test_exact_camry_profile_and_guard(self):
    self.assertEqual(self.profile.document["schema"], "toyota-diagnostics-registry-v4")
    self.assertEqual(self.profile.name, "camry-2026-f33")
    self.assertEqual(self.profile.bus, 0)
    self.assertEqual(self.profile.fault_status_mask, 0xAF)
    self.assertEqual([(ecu.name, ecu.address) for ecu in self.profile.scanned_ecus()], support.CAMRY_ECUS)
    self.assertEqual(self.profile.legislated_responders, frozenset(support.LEGISLATED_RESPONDERS))
    self.assertEqual(self.profile.mode04_request, bytes.fromhex("0104000000000000"))
    self.assertEqual((self.profile.guard.ecu_key, self.profile.guard.did, self.profile.guard.contains),
                     ("eps", 0xF181, support.EXPECTED_EPS_F181))

  def test_topology_and_observed_identities(self):
    topology = self.profile.gts_can_topology
    self.assertIsNotNone(topology)
    self.assertEqual((topology["vehicle_type"], topology["vehicle_name"], topology["can_bus_car_id"]),
                     (12704, "Camry HV", "0x00A7D910"))
    self.assertEqual((topology["option_count"], topology["placement_variant_count"]), (18, 1))
    placements = {row["ecu_domain"]: row for row in topology["placement_variants"][0]["placements"]}
    self.assertEqual(placements["Front Camera Module"]["bus_name"], "Bus 1")
    self.assertEqual(placements["Power Steering (EPS)"]["bus_name"], "Bus 4")
    self.assertEqual(placements["Skid Control (ABS/VSC/TRAC)"]["bus_name"], "Bus 4")
    self.assertIn("not Panda logical bus numbers", topology["namespace_boundary"])

    eps = self.profile.observed_identity("eps")
    frc = self.profile.observed_identity("frc")
    brake = self.profile.observed_identity("brake")
    self.assertEqual(eps["f181_software_ids"], ["8965F3307000", "8A3113303100"])
    self.assertEqual(eps["f18c_serial"], "8965033K9011J2740743")
    self.assertEqual((frc["f181_software_ids"], frc["ecu_part_0105"], frc["f18c_serial"]),
                     (["8646F3315000"], "8646C06091", "TN69400026030404235J"))
    self.assertEqual((brake["f181_software_ids"], brake["ecu_part_0105"], brake["f18c_serial"]),
                     (["F152633K0000"], "8954147040", "8954147040CFC1800985"))
    for identity in (eps, frc, brake):
      self.assertEqual((identity["panda_bus_at_observation"], identity["elm327_param"]), (1, 1))
      self.assertIn("current profile diagnostic route is post-repin Panda bus0", identity["route_note"])

  def test_gts_catalog_witnesses(self):
    did, signals = self.profile.resolve_did("frc", "LTA Control Condition")
    self.assertEqual(did, 0x1601)
    self.assertTrue(any(row["name"] == "LTA Control Condition" for row in signals))
    self.assertTrue(all(row["decoder"] == "p5-linear-msb0-v1" for row in signals))
    self.assertEqual(self.profile.describe_dtc("frc", "U013187")[0]["failure"], "Missing Message")
    test = self.profile.lookup_active_test("frc", "0xA429")
    self.assertEqual((test["routine_id"], test["start_static"], test["stop_static"], test["result_static"]),
                     (0x1588, "31011588", "31021588", "31031588"))
    self.assertEqual((test["execution"], test["session_requirement"]), ("executable", "extended"))

  def test_v4_lifecycle_plugins_and_utility_family_metadata(self):
    session = self.profile.session_control
    self.assertEqual((session["generation"], session["enter_sequence"], session["return_default"]),
                     ("current-p5", ["1001", "1003"], "1001"))
    self.assertEqual(session["wire_proven_categories"], [397, 435, 498])
    self.assertEqual(session["keepalive"]["request"], "22f186")
    comm_set_id, commset = self.profile.session_commset("frc")
    self.assertEqual((comm_set_id, commset["receive_timeout"], commset["retry_count"]), (1, 1020, 1))
    plugins = self.profile.roles("frc")
    self.assertTrue(any(row["role"] == 5 and row["dll"] == "GetDatMonListP5_DT.dll" for row in plugins))
    self.assertEqual(len(self.profile.utility_bindings()), 10)
    self.assertEqual(self.profile.lookup_utility_family("0xD4")["semantic_kind"], "single_routine_active_test")
    self.assertEqual(self.profile.utilities("frc"), [])

  def test_dtc_status_names_match_opendbc(self):
    self.assertEqual(registry.decode_status_bits(0xAF), get_dtc_status_names(0xAF))


if __name__ == "__main__":
  unittest.main()
