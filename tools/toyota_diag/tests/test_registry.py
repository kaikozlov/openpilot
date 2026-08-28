import unittest

from opendbc.car.uds import get_dtc_status_names

from tools.toyota_diag import registry
from tools.toyota_diag.tests import support


class TestRegistry(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.profile = registry.load_registry()

  def test_exact_camry_profile_and_guard(self):
    self.assertEqual(self.profile.document["schema"], "toyota-diagnostics-registry-v2")
    self.assertEqual(self.profile.name, "camry-2026-f33")
    self.assertEqual(self.profile.bus, 0)
    self.assertEqual(self.profile.fault_status_mask, 0xAF)
    self.assertEqual([(ecu.name, ecu.address) for ecu in self.profile.scanned_ecus()], support.CAMRY_ECUS)
    self.assertEqual(self.profile.legislated_responders, frozenset(support.LEGISLATED_RESPONDERS))
    self.assertEqual(self.profile.mode04_request, bytes.fromhex("0104000000000000"))
    self.assertEqual((self.profile.guard.ecu_key, self.profile.guard.did, self.profile.guard.contains),
                     ("eps", 0xF181, support.EXPECTED_EPS_F181))

  def test_gts_catalog_witnesses(self):
    did, signals = self.profile.resolve_did("frc", "LTA Control Condition")
    self.assertEqual(did, 0x1601)
    self.assertTrue(any(row["name"] == "LTA Control Condition" for row in signals))
    self.assertTrue(all(row["decoder"] == "p5-linear-msb0-v1" for row in signals))
    self.assertEqual(self.profile.describe_dtc("frc", "U013187")[0]["failure"], "Missing Message")
    test = self.profile.lookup_active_test("frc", "0xA429")
    self.assertEqual((test["routine_id"], test["start_static"], test["stop_static"], test["result_static"]),
                     (0x1588, "31011588", "31021588", "31031588"))

  def test_dtc_status_names_match_opendbc(self):
    self.assertEqual(registry.decode_status_bits(0xAF), get_dtc_status_names(0xAF))


if __name__ == "__main__":
  unittest.main()
