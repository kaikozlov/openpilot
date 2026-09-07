import unittest

from opendbc.car.uds import MessageTimeoutError

from tools.toyota_diag import registry, resolver
from tools.toyota_diag.tests import support


class TestVehicleResolver(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.profile = registry.load_registry(registry.LEGACY_CAMRY_REGISTRY)

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
    self.assertEqual(current.supported_dids(), (0x1600, 0x1601))
    self.assertEqual(scripted.calls.count((0x792, "read_did", 0x0101)), 1)
    self.assertEqual(scripted.calls.count((0x792, "read_did", 0x1600)), 1)


  def test_p5_root_ids_remain_supported_and_reserved_groups_are_not_queried(self):
    scripted = support.ScriptedUds()
    root = bytearray(32)
    for index in (0xF3, 0xFD):
      root[index // 8] |= 0x80 >> (index % 8)
    scripted.did[0x792] = {0x0101: bytes(root)}
    current = resolver.P5DidSupportResolver.from_profile(self.profile, scripted.factory(0x792))
    self.assertEqual(current.supported_groups(), (0xF300, 0xFD00))
    self.assertTrue(current.supports(0xF300))
    self.assertTrue(current.supports(0xFD00))
    self.assertFalse(current.supports(0xF301))
    self.assertFalse(current.supports(0xFD01))
    self.assertEqual(current.supported_dids(), (0xF300, 0xFD00))
    self.assertNotIn((0x792, "read_did", 0xF300), scripted.calls)
    self.assertNotIn((0x792, "read_did", 0xFD00), scripted.calls)

  def test_p6_support_uses_selector_and_member_bitmaps_without_can_route_assumptions(self):
    profile = registry.ToyotaDatabase.load().profile("NA", 12991)
    self.assertEqual(resolver.support_mode(profile, 6000), "p6-standard")
    scripted = support.ScriptedUds()
    root = bytearray(32)
    for index in (0x02, 0xFD):
      root[index // 8] |= 0x80 >> (index % 8)
    # A102 member bitmap: bit1 advertises DID 0x0201. A1FD is a Toyota-reserved
    # selector that remains supported but is not expanded with a second request.
    scripted.did[0x123] = {0xA100: bytes(root), 0xA102: bytes.fromhex("40")}
    current = resolver.P6DidSupportResolver.from_profile(profile, scripted.factory(0x123))
    self.assertEqual(current.supported_groups(), (0xA102, 0xA1FD))
    self.assertTrue(current.supports(0xA102))
    self.assertTrue(current.supports(0xA1FD))
    self.assertTrue(current.supports(0x0201))
    self.assertFalse(current.supports(0x0200))
    self.assertEqual(current.supported_dids(), (0xA102, 0xA1FD, 0x0201))
    self.assertEqual(scripted.calls.count((0x123, "read_did", 0xA100)), 1)
    self.assertEqual(scripted.calls.count((0x123, "read_did", 0xA102)), 1)
    self.assertNotIn((0x123, "read_did", 0xA1FD), scripted.calls)

  def test_p6_rid_support_uses_d1_selector_hierarchy(self):
    profile = registry.ToyotaDatabase.load().profile("NA", 12165, bus=0)
    scripted = support.ScriptedUds()
    endpoint = 0x18DA00F1
    root = bytearray(32)
    for index in (0x02, 0xF0):
      root[index // 8] |= 0x80 >> (index % 8)
    scripted.routine[(endpoint, 1, 0xD100)] = bytes(root)
    scripted.routine[(endpoint, 1, 0xD102)] = bytes.fromhex("40")
    current = resolver.P6RidSupportResolver.from_profile(profile, scripted.factory(endpoint))
    self.assertEqual(current.supported_groups(), (0xD102, 0xD1F0))
    self.assertTrue(current.supports(0xD102))
    self.assertTrue(current.supports(0xD1F0))
    self.assertTrue(current.supports(0x0201))
    self.assertFalse(current.supports(0x0200))
    self.assertFalse(current.supports(0xF001))
    self.assertEqual(current.supported_rids(), (0xD102, 0xD1F0, 0x0201))
    self.assertEqual(scripted.calls.count((endpoint, "routine", 1, 0xD100, b"")), 1)
    self.assertEqual(scripted.calls.count((endpoint, "routine", 1, 0xD102, b"")), 1)
    self.assertNotIn((endpoint, "routine", 1, 0xD1F0, b""), scripted.calls)

  def test_p6_route_materializes_normal_fixed_physical_can_id(self):
    profile = registry.ToyotaDatabase.load().profile("NA", 12165)
    ecu = profile.lookup_ecu(6000)
    _, route = resolver.lookup_mount_candidate(profile, 6000)
    self.assertIsNone(profile.bus)
    self.assertEqual(ecu.endpoint, (0x18DA00F1, None))
    self.assertEqual(ecu.request_address_field, 0)
    self.assertEqual(ecu.transport_kind, "iso15765-29bit-normal-fixed")
    self.assertTrue(ecu.uds_transport_supported)
    self.assertEqual(route.endpoint, (0x18DA00F1, None))
    self.assertEqual(route.request_address_field, 0)
    self.assertEqual(route.as_dict()["controller"], "CCommCtrlISO15765_29BitCan")

  def test_mount_routes_are_toyota_category_phase_routes(self):
    routes = {route.category_id: route for _, route in resolver.mount_routes(self.profile)}
    self.assertEqual(len(routes), 34)
    self.assertEqual(routes[409].endpoint, (0x7C0, None))
    self.assertEqual(routes[498].endpoint, (0x792, None))
    self.assertEqual(routes[452].endpoint, (0x750, 0x2A))
    self.assertEqual(routes[466].endpoint, (0x750, 0x29))
    self.assertEqual(routes[470].endpoint, (0x750, 0x7B))
    self.assertEqual(routes[492].endpoint, (0x750, 0x96))
    self.assertTrue(resolver.support_family(self.profile, routes[452].category_id) == "p5")
    self.assertFalse(resolver.support_family(self.profile, routes[148].category_id) == "p5")
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
    self.assertEqual((master["live_state"], master["transport_responded"]), ("probe_unavailable", None))
    self.assertFalse(master["probe_available"])
    self.assertIn(((0x750, 0x2A), "read_did", 0x0101), scripted.calls)
    self.assertEqual([call for call in scripted.calls if call[0] == 0x7C0], [(0x7C0, "read_did", 0x0101)])

  def test_v3_registry_has_no_invented_vehicle_resolver(self):
    legacy = support.load_profile(None)
    with self.assertRaisesRegex(resolver.ResolverError, "requires registry v5\\+"):
      resolver.resolve_profile_vin(legacy, "XXXXAXXKXSX123456")


if __name__ == "__main__":
  unittest.main()
