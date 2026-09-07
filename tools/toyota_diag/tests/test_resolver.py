import unittest

from opendbc.car.uds import MessageTimeoutError

from tools.toyota_diag import registry, resolver
from tools.toyota_diag.tests import support


class TestVehicleResolver(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.profile = registry.load_registry()

  def test_current_camry_vin_decision_wildcards_and_branches(self):
    raw = self.profile.vehicle_resolution["vin_decision"]
    row_a, row_b = raw["rows"]
    vin_a = "XXXXAXXKXSX123456"
    vin_b = "XXXXBXXKXSX123456"
    vin_bad = "XXXXCXXKXSX123456"
    self.assertTrue(resolver.vin_decision_matches(row_a, vin_a, category_id=372, phase_type=0x12))
    self.assertTrue(resolver.vin_decision_matches(row_b, vin_b, category_id=372, phase_type=0x12))
    self.assertFalse(resolver.vin_decision_matches(row_a, vin_bad, category_id=372, phase_type=0x12))
    self.assertFalse(resolver.vin_decision_matches(row_a, vin_a, category_id=373, phase_type=0x12))
    self.assertFalse(resolver.vin_decision_matches(row_a, vin_a, category_id=372, phase_type=0x13))
    match = resolver.resolve_profile_vin(self.profile, vin_a)
    self.assertEqual((match["vehicle_type"], match["vehicle_name"]), (12704, "Camry HV"))
    self.assertEqual((match["source_category_id"], match["source_phase_type"]), (372, 0x12))
    self.assertEqual(match["install_set_ids"], [8119, 8120, 8121, 27706])
    self.assertIsNone(resolver.resolve_profile_vin(self.profile, vin_bad))

  def test_support_bitmap_exact_msb_first_expansion(self):
    self.assertEqual(resolver.analyze_support_bitmap(0, bytes.fromhex("c080"), 8), [0x0000, 0x0100, 0x0800])
    self.assertEqual(resolver.analyze_support_bitmap(0x5200, bytes.fromhex("a0"), 0), [0x5201, 0x5203])
    self.assertEqual(resolver.analyze_support_bitmap(0x5200, bytes(31) + b"\x01", 0), [])

  def test_live_did_support_queries_root_once_and_groups_lazily(self):
    scripted = support.ScriptedUds()
    # Root group 0x16: bit index 22 => byte2 bit6 (0x02). Group member 0x1601 => bit0 (0x80).
    scripted.did[0x792] = {0x0101: bytes.fromhex("000002"), 0x1600: bytes.fromhex("80")}
    current = resolver.P5DidSupportResolver.from_profile(self.profile, scripted.factory(0x792))
    self.assertEqual(current.root_did, 0x0101)
    self.assertEqual(current.supported_groups(), (0x1600,))
    self.assertTrue(current.supports(0x1601))
    self.assertFalse(current.supports(0x1602))
    self.assertFalse(current.supports(0x1701))
    self.assertEqual(current.supported_dids(), (0x1601,))
    self.assertEqual(scripted.calls.count((0x792, "read_did", 0x0101)), 1)
    self.assertEqual(scripted.calls.count((0x792, "read_did", 0x1600)), 1)

  def test_mount_routes_are_toyota_category_phase_routes(self):
    routes = {route.category_id: route for _, route in resolver.mount_routes(self.profile)}
    self.assertEqual(len(routes), 34)
    self.assertEqual(routes[409].endpoint, (0x7C0, None))
    self.assertEqual(routes[498].endpoint, (0x792, None))
    self.assertEqual(routes[452].endpoint, (0x750, 0x2A))
    self.assertEqual(routes[466].endpoint, (0x750, 0x29))
    self.assertEqual(routes[470].endpoint, (0x750, 0x7B))
    self.assertEqual(routes[492].endpoint, (0x750, 0x96))
    self.assertTrue(resolver.uses_current_p5_path(self.profile, routes[452]))
    self.assertFalse(resolver.uses_current_p5_path(self.profile, routes[148]))
    self.assertEqual(resolver.lookup_mount_candidate(self.profile, "frc")[1].category_id, 498)
    self.assertEqual(resolver.lookup_mount_candidate(self.profile, "Tire Pressure Monitor")[1].category_id, 452)

  def test_mount_probe_uses_toyota_routes_including_extended_addressing(self):
    scripted = support.ScriptedUds()
    scripted.did[0x792] = {0x0101: bytes(32)}
    scripted.did[(0x750, 0x2A)] = {0x0101: bytes(32)}
    scripted.did[0x7C0] = {0x0101: MessageTimeoutError()}
    rows = resolver.probe_mount_candidates(self.profile, scripted.factory)
    self.assertEqual(len(rows), 34)
    self.assertEqual(len({row["category_id"] for row in rows}), 34)
    self.assertEqual(next(row for row in rows if row["category_id"] == 498)["live_state"], "responding")
    self.assertEqual(next(row for row in rows if row["category_id"] == 452)["live_state"], "responding")
    self.assertEqual(next(row for row in rows if row["category_id"] == 409)["live_state"], "no_response")
    master = next(row for row in rows if row["category_id"] == 148)
    self.assertEqual((master["live_state"], master["transport_responded"]), ("not_current_p5", None))
    self.assertIn(((0x750, 0x2A), "read_did", 0x0101), scripted.calls)
    self.assertEqual([call for call in scripted.calls if call[0] == 0x7C0], [(0x7C0, "read_did", 0x0101)])

  def test_v3_registry_has_no_invented_vehicle_resolver(self):
    legacy = support.load_profile(None)
    with self.assertRaisesRegex(resolver.ResolverError, "requires registry v5\\+"):
      resolver.resolve_profile_vin(legacy, "XXXXAXXKXSX123456")


if __name__ == "__main__":
  unittest.main()
