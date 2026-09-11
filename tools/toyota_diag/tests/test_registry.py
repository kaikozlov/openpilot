import unittest

from opendbc.car.uds import get_dtc_status_names

from tools.toyota_diag import registry, resolver
from tools.toyota_diag.tests import support


class TestRegistry(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.profile = registry.load_registry(registry.LEGACY_CAMRY_REGISTRY)

  def test_exact_camry_profile_and_guard(self):
    self.assertEqual(self.profile.document["schema"], "toyota-diagnostics-registry-v6")
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

  def test_v6_resolver_lifecycle_plugins_and_utility_family_metadata(self):
    resolver = self.profile.vehicle_resolution
    self.assertEqual((resolver["vehicle_type"], resolver["vehicle_name"], resolver["install_set_ids"]),
                     (12704, "Camry HV", [8119, 8120, 8121, 27706]))
    self.assertEqual(len(self.profile.mount_candidates()), 34)
    self.assertEqual({row["connection_frame_id"] for row in self.profile.mount_candidates()}, {0})
    self.assertEqual({row["connection_comm_set_id"] for row in self.profile.mount_candidates()}, {9})
    self.assertEqual({row["connection_phase_type"] for row in self.profile.mount_candidates()}, {0x12, 0x22})
    self.assertTrue(all("direct_address" not in row for row in self.profile.mount_candidates()))
    routes = {row["category_id"]: row["transport_route"] for row in self.profile.mount_candidates()}
    self.assertEqual((routes[409]["request_address"], routes[409]["address_extension"]), (0x7C0, 0))
    self.assertEqual((routes[452]["request_address"], routes[452]["address_extension"]), (0x750, 0x2A))
    self.assertEqual((routes[498]["request_address"], routes[498]["address_extension"]), (0x792, 0))
    session = self.profile.session_control
    self.assertEqual((session["generation"], session["enter_sequence"], session["return_default"]),
                     ("current-p5", ["1001", "1003"], "1001"))
    self.assertEqual(session["eligible_generation_low5"], ["0x14", "0x15", "0x16"])
    self.assertNotIn("wire_proven_categories", session)
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


class TestUniversalToyotaDatabase(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.database = registry.ToyotaDatabase.load()

  def test_bundle_covers_all_current_regions_and_keeps_offline_categories_unrouted(self):
    self.assertEqual(self.database.index["schema"], registry.BUNDLE_SCHEMA)
    self.assertEqual(set(self.database.index["regions"]), {"NA", "EU", "JP"})
    self.assertEqual(set(self.database.index["support_contracts"]), {"p5", "p6"})
    expected = {"NA": (2864, 135, 479), "EU": (6057, 161, 554), "JP": (1868, 143, 589)}
    for region, (vehicle_count, catalog_count, route_count) in expected.items():
      counts = self.database.region_index(region)["counts"]
      self.assertEqual(counts["vehicle_count"], vehicle_count)
      self.assertEqual(counts["category_count"], 2136)
      self.assertEqual(counts["catalog_count"], catalog_count)
      self.assertEqual(counts["support_family_counts"], {"p3": 1, "p4": 1859, "p5": 172, "p6": 104})
      self.assertEqual(counts["support_mode_counts"], {
        "p3": 1, "p4": 1859, "p5-hino": 3, "p5-mazda": 11, "p5-standard": 114,
        "p5-subaru": 24, "p5-suzuki": 20, "p6-standard": 104,
      })
      self.assertEqual(counts["route_count"], route_count)
      self.assertEqual(counts["route_count"], len(self.database.region_index(region)["routes"]))
    offline = self.database.profile("NA")
    self.assertEqual(len(offline.ecus), 135)
    self.assertFalse(offline.lookup_ecu("frc").route_resolved)
    self.assertIsNone(offline.vehicle_resolution)

  def test_universal_profile_has_no_implicit_panda_bus_and_category_ids_are_first_class(self):
    profile = self.database.profile("NA", 12165)
    self.assertIsNone(profile.bus)
    self.assertEqual(profile.lookup_ecu(6000).category_id, 6000)
    self.assertEqual(profile.lookup_ecu("6000").category_id, 6000)
    self.assertEqual(profile.lookup_ecu("0x18DA00F1").category_id, 6000)
    with self.assertRaisesRegex(registry.RegistryError, "no Panda diagnostic bus is bound"):
      registry.require_panda_bus(profile)
    self.assertEqual(registry.require_panda_bus(self.database.profile("NA", 12165, bus=2)), 2)

  def test_camry_is_derived_from_toyota_vehicle_install_and_route_tables(self):
    profile = self.database.profile("NA", 12704)
    self.assertEqual((profile.vehicle_type, profile.vehicle), (12704, "Toyota Camry HV"))
    self.assertEqual(profile.vehicle_resolution["install_set_ids"], [8119, 8120, 8121, 27706])
    self.assertEqual(len(profile.mount_candidates()), 34)
    self.assertEqual(len(profile.ecus), 34)  # every routed Toyota install candidate survives catalog/family tooling gaps
    self.assertEqual(profile.lookup_ecu("frc").endpoint, (0x792, None))
    engine = profile.lookup_ecu("engine")
    self.assertEqual(engine.functional_response, 0x7E8)
    engine_route = next(row["transport_route"] for row in profile.mount_candidates() if row["category_id"] == 372)
    self.assertEqual(engine_route["legislated_request_address"], 0x7E0)
    self.assertNotIn("legislated_response_address", engine_route)
    self.assertEqual(profile.lookup_ecu("Tire Pressure Monitor").endpoint, (0x750, 0x2A))
    self.assertEqual(profile.lookup_ecu("Combination Meter").endpoint, (0x7C0, None))
    self.assertEqual(profile.resolve_did("frc", "LTA Control Condition")[0], 0x1601)

  def test_lookup_skips_routed_ecus_without_catalogs(self):
    profile = self.database.profile("NA", 12862)
    self.assertTrue(any(ecu.category_id is not None and profile.category(ecu) is None for ecu in profile.ecus))
    self.assertEqual(profile.lookup_ecu("frc").key, "frc")


  def test_support_modes_follow_toyota_family_local_dispatch(self):
    profile = self.database.profile("NA", 12704)
    self.assertEqual(resolver.support_mode(profile, 498), "p5-standard")
    categories = self.database.region_index("NA")["categories"]
    self.assertEqual(categories["722"]["support_mode"], "p5-subaru")
    self.assertEqual(categories["8500"]["support_mode"], "p5-suzuki")
    self.assertEqual(categories["851"]["support_mode"], "p5-mazda")
    self.assertEqual(categories["5033"]["support_mode"], "p5-hino")
    self.assertEqual(categories["6000"]["support_mode"], "p6-standard")

  def test_non_camry_vehicle_uses_the_same_database_pipeline(self):
    profile = self.database.profile("NA", 12757)
    self.assertEqual(profile.vehicle, "Toyota 4Runner")
    self.assertEqual(len(profile.mount_candidates()), 35)
    self.assertEqual(len(profile.ecus), 35)
    self.assertTrue(all(ecu.route_resolved for ecu in profile.ecus))
    self.assertTrue(all(ecu.route_resolved for ecu in profile.ecus))
    self.assertEqual(len(profile.ecus), 35)

  def test_p4_vin_hit_remains_nonfinal_until_toyota_type41_stage(self):
    # Current NA type-59 row: category 60 / phase 0x12 / vehicle 10877.
    # VIN10 dispatches generation-low5 4 through CGetCarInfoPhase4, which then
    # runs the Spe 0x28..0x39 probe program and class-0x129 type-41 decision.
    matches = self.database.resolve_vin("NA", "XX1KEXXEXAX123456")
    self.assertEqual(len(matches), 1)
    self.assertEqual(matches[0]["vehicle_type"], 10877)
    self.assertEqual(matches[0]["resolver_stages"], ["requires_type41_vehicle_decision"])
    self.assertFalse(matches[0]["resolution_complete"])

  def test_vin_decision_resolves_camry_without_a_camry_profile(self):
    for vin in ("XXXXAXXKXSX123456", "XXXXBXXKXSX123456"):
      matches = self.database.resolve_vin("NA", vin, rx_address=0x7E8)
      self.assertEqual([(row["vehicle_type"], row["name"]) for row in matches], [(12704, "Camry HV")])
    self.assertEqual(self.database.resolve_vin("NA", "XXXXCXXKXSX123456", rx_address=0x7E8), [])


if __name__ == "__main__":
  unittest.main()
