import unittest

from tsk.lib.camry_f33 import (
  CAMRY_F33_APP_F181,
  CAMRY_F33_APPLICATION_RUNTIME,
  CAMRY_F33_B6,
  CAMRY_F33_CHECKPOINT,
  CAMRY_F33_CODEFLASH,
  CAMRY_F33_CRUISE,
  CAMRY_F33_LATERAL_PORT,
  CAMRY_F33_EPS_394_STATE_CANDIDATES,
  CAMRY_F33_GEAR,
  CAMRY_F33_MODULES,
  CAMRY_F33_OPENDBC,
  CAMRY_F33_RAM_RECOVERY,
  CAMRY_F33_PRODUCTION_ARCHITECTURE,
  CAMRY_F33_READY,
  CAMRY_F33_REMAINING_RESEARCH_BOUNDARIES,
  CAMRY_F33_TX_STATUS,
  CAMRY_F33_LATERAL_REQUEST,
  public_camry_f33_status,
)


class TestCamryF33Evidence(unittest.TestCase):
  def test_exact_identity_and_module_routes(self):
    self.assertEqual(CAMRY_F33_APP_F181.hex(),
                     "023839363546333330373030300000000038413331313333303331303000000000")
    self.assertEqual(CAMRY_F33_MODULES["eps"]["f181"], "8965F3307000")
    self.assertEqual(CAMRY_F33_MODULES["frc"]["f181"], "8646F3315000")
    self.assertEqual(CAMRY_F33_MODULES["brake_epb"]["f181"], "F152633K0000")
    self.assertEqual((CAMRY_F33_MODULES["frc"]["request"], CAMRY_F33_MODULES["frc"]["response"]), (0x792, 0x79A))
    self.assertEqual((CAMRY_F33_MODULES["brake_epb"]["request"], CAMRY_F33_MODULES["brake_epb"]["response"]), (0x7B0, 0x7B8))

  def test_ready_gear_and_cruise_dynamic_joins(self):
    self.assertEqual(CAMRY_F33_READY["address"], 0x51E)
    self.assertEqual((CAMRY_F33_READY["nrtd"], CAMRY_F33_READY["ready"]), (0, 1))
    self.assertEqual(CAMRY_F33_GEAR, {0: "P", 1: "R", 2: "N", 3: "D", 4: "B"})
    self.assertEqual(CAMRY_F33_CRUISE["momentary_switch_carrier"]["address"], 0x0FE)
    self.assertEqual(CAMRY_F33_CRUISE["momentary_switch_tuples"]["main"], (0x3F, 0x00, 0xC3, 0x66))
    self.assertEqual(CAMRY_F33_CRUISE["brake_107e_default_extended"], "requestOutOfRange")

  def test_exact_codeflash_and_bootstrap_result(self):
    self.assertEqual(CAMRY_F33_CODEFLASH["raw_transport_size"], 0x200000)
    self.assertEqual(CAMRY_F33_CODEFLASH["normalized_size"], 0x100000)
    self.assertEqual(CAMRY_F33_CODEFLASH["raw_transport_sha256"],
                     "b588c7258699beee77669d1f5f09bb17ef8b189b941b46f344a07378c3aaa727")
    self.assertEqual(CAMRY_F33_CODEFLASH["normalized_sha256"],
                     "42dce8efc42f6ae31718e7713fa2d26bb9191b4a82439778aee4d7afded9b0e7")
    self.assertEqual(CAMRY_F33_CODEFLASH["boot_stack"], "old")
    self.assertEqual(CAMRY_F33_CODEFLASH["successful_words"], 524288)

  def test_target_native_b6_contract_is_non_policy(self):
    self.assertEqual(CAMRY_F33_B6["address"], 0x0B6)
    self.assertEqual(CAMRY_F33_B6["pdu"], 44)
    self.assertEqual(CAMRY_F33_B6["protected_rx_ids"], (0x00F, 0x0D7, 0x0B6))
    self.assertEqual(CAMRY_F33_B6["crypto_selector"], 4)
    self.assertEqual(CAMRY_F33_B6["icus_command"], 7)
    self.assertEqual(CAMRY_F33_B6["target_lateral_id"]["lta_lca"], 11)
    self.assertEqual(CAMRY_F33_B6["target_steering_angle"]["absolute_max_raw"], 1745)
    self.assertEqual(CAMRY_F33_B6["target_steering_angle"]["delta_max_per_effective_gap_raw"], 78)
    self.assertEqual(CAMRY_F33_B6["nominal_rx_timeout_ms"], 35.0)

  def test_target_native_tx_status_producer_closure(self):
    self.assertEqual(CAMRY_F33_TX_STATUS["first_five_tx_pdus"], (0x030, 0x351, 0x394, 0x4A3, 0x4C8))
    self.assertEqual(CAMRY_F33_TX_STATUS["packers"][0x351], 0x4CED0)
    self.assertEqual(CAMRY_F33_TX_STATUS["packers"][0x394], 0x4CE08)
    self.assertEqual(CAMRY_F33_TX_STATUS["packers"][0x4A3], (0x4C000, 0x4C14E, 0x4C7AA))
    self.assertEqual(CAMRY_F33_TX_STATUS["driver_torque_direct_references"],
                     {"total": 9, "reads": 7, "writes": 2})
    self.assertEqual(CAMRY_F33_TX_STATUS["motor_q_current_direct_references"],
                     {"total": 6, "reads": 4, "writes": 2})
    self.assertEqual(CAMRY_F33_TX_STATUS["can_4a3_alternate_current_source_direct_references"], 4)
    self.assertFalse(CAMRY_F33_TX_STATUS["can_4a3_b6_b7_is_did_1151_q_current"])
    self.assertNotEqual(CAMRY_F33_TX_STATUS["can_4a3_b6_b7_source_gp_offset"],
                        CAMRY_F33_TX_STATUS["did_1151_q_current_source_gp_offset"])

  def test_exact_394_projection_preserves_lossy_candidates(self):
    self.assertEqual(CAMRY_F33_EPS_394_STATE_CANDIDATES[(0, 0, 0, 0)], (0,))
    self.assertEqual(CAMRY_F33_EPS_394_STATE_CANDIDATES[(0, 3, 0, 0)], (1, 3, 4))
    self.assertEqual(CAMRY_F33_EPS_394_STATE_CANDIDATES[(0, 7, 0, 0)], (2, 16))
    self.assertEqual(CAMRY_F33_EPS_394_STATE_CANDIDATES[(2, 3, 2, 1)], (6,))

  def test_key_recovery_and_application_runtime_boundaries(self):
    self.assertEqual(CAMRY_F33_RAM_RECOVERY["raw_key_scan_survivors"], 0)
    self.assertEqual(CAMRY_F33_RAM_RECOVERY["dataflash_object15_valid_copies"], 0)
    self.assertFalse(CAMRY_F33_APPLICATION_RUNTIME["low_boot_staging_retained_after_stock_startup"])
    self.assertEqual(CAMRY_F33_APPLICATION_RUNTIME["retained_exec_tail_start"], 0xFEBFF9F0)
    self.assertEqual(CAMRY_F33_APPLICATION_RUNTIME["retained_exec_tail_size"], 524)
    self.assertEqual(CAMRY_F33_APPLICATION_RUNTIME["xcp_write_window"], (0xFEBF7C00, 0xFEBFFBFF))
    self.assertTrue(CAMRY_F33_APPLICATION_RUNTIME["rid_100f_reaches_command5"])
    self.assertFalse(CAMRY_F33_APPLICATION_RUNTIME["rid_100f_general_secoc_signer"])
    self.assertEqual(CAMRY_F33_APPLICATION_RUNTIME["application_control_transfer_into_tail"], "not-recovered")
    self.assertEqual(CAMRY_F33_CHECKPOINT["cpu_visible_key_recovery"], "negative")
    self.assertIn("protected", CAMRY_F33_CHECKPOINT["key_storage"])
    self.assertIn("ordinary-dataflash", CAMRY_F33_CHECKPOINT["key_storage"])
    self.assertEqual(CAMRY_F33_CHECKPOINT["static_receiver_integration"], "closed")
    self.assertEqual(CAMRY_F33_PRODUCTION_ARCHITECTURE["runtime_model"], "RAM-only / reset-to-stock")
    self.assertEqual(CAMRY_F33_PRODUCTION_ARCHITECTURE["persistent_flash"], "fallback-only")
    self.assertFalse(CAMRY_F33_PRODUCTION_ARCHITECTURE["ready"])
    self.assertEqual([row["rank"] for row in CAMRY_F33_PRODUCTION_ARCHITECTURE["ranking"]], [1, 2, 3, 4])

  def test_exact_f33_uses_normal_port_shape(self):
    self.assertIn("SafetyModel.toyota", CAMRY_F33_OPENDBC["safety"])
    self.assertIn("TSS3", CAMRY_F33_OPENDBC["safety"])
    self.assertNotIn("ALLOW_DEBUG", CAMRY_F33_OPENDBC["safety"])
    self.assertNotIn("noOutput-default", CAMRY_F33_OPENDBC["mode"])
    self.assertTrue(CAMRY_F33_OPENDBC["controller_can_output"])
    self.assertNotIn("development_sender_available", CAMRY_F33_OPENDBC)
    self.assertNotIn("development_controller_can_output", CAMRY_F33_OPENDBC)
    self.assertTrue(CAMRY_F33_OPENDBC["supported_output"])
    self.assertTrue(CAMRY_F33_OPENDBC["lateral_request_decoding"])

    self.assertTrue(CAMRY_F33_LATERAL_PORT["available"])
    self.assertEqual(CAMRY_F33_LATERAL_PORT["status"], "native-port-gate2-patched-eps")
    self.assertIn("removed", CAMRY_F33_LATERAL_PORT["superseded"])
    self.assertIn("ToyotaEphemeralSecOCBridge", CAMRY_F33_LATERAL_PORT["superseded"])
    self.assertIn("CC.latActive", CAMRY_F33_LATERAL_PORT["engagement"])
    self.assertNotIn("ToyotaEphemeralSecOCBridge", CAMRY_F33_LATERAL_PORT["engagement"])
    self.assertIn("not ALLOW_DEBUG", CAMRY_F33_LATERAL_PORT["safety"])
    self.assertIn("0x08A bit 27", CAMRY_F33_LATERAL_PORT["safety"])
    self.assertIn("Gate-2", CAMRY_F33_LATERAL_PORT["receiver_acceptance"])
    self.assertIn("protected key", CAMRY_F33_LATERAL_PORT["receiver_acceptance"])
    self.assertIn("stock-ACC cancel", CAMRY_F33_LATERAL_PORT["unsupported_features"])
    self.assertIn("driver-override", CAMRY_F33_LATERAL_PORT["unsupported_features"])
    self.assertTrue(CAMRY_F33_LATERAL_PORT["supported_output"])

    self.assertEqual(CAMRY_F33_CHECKPOINT["state"], "normal-port-supported-patched-eps")
    self.assertIn("Gate-2", CAMRY_F33_CHECKPOINT["output_detail"])
    self.assertIn("stock-ACC cancel", CAMRY_F33_CHECKPOINT["unsupported_feature"])

    status = public_camry_f33_status()
    self.assertNotIn("development_lateral", status)
    self.assertIn("lateral_port", status)
    self.assertEqual(status["lateral_port"], CAMRY_F33_LATERAL_PORT)
    self.assertEqual(status["eps_394_state_candidates"], CAMRY_F33_EPS_394_STATE_CANDIDATES)
    self.assertEqual(status["application_runtime"], CAMRY_F33_APPLICATION_RUNTIME)
    self.assertTrue(status["supported_output"])
    self.assertEqual(tuple(status["remaining_research_boundaries"]), CAMRY_F33_REMAINING_RESEARCH_BOUNDARIES)
    self.assertEqual(len(status["remaining_research_boundaries"]), 5)
    self.assertIn("stock-ACC cancel", status["remaining_research_boundaries"][0])
    self.assertIn("driver-override", status["remaining_research_boundaries"][1])
    self.assertIn("RAM-only", status["remaining_research_boundaries"][4])

  def test_lateral_request_is_representation_not_ingress(self):
    req = CAMRY_F33_LATERAL_REQUEST
    self.assertEqual(req["address"], 0x08A)
    self.assertEqual(req["target_lateral_id"]["observed"], (0, 11, 18))
    self.assertEqual(req["sequence"]["modulus"], 64)
    self.assertAlmostEqual(req["target_steering_angle"]["scale_deg_per_count"], 1024 / 17870)
    self.assertFalse(req["eps_ingress"])
    self.assertFalse(req["eps_generated_com_transmit"])
    self.assertFalse(req["stock_lta_requires_b6"])
    self.assertIn("ordinary-SecOC structural match", req["security_trailer"]["classification"])
    self.assertIn("no 0x08A-to-B6 transform", req["boundary"])
    self.assertEqual(req["observed_buses"]["panda_bus1"], 0)
    self.assertIn("encoding assumptions", req["encoding_caveat"])
    self.assertIn("unknown", req["producer"])


if __name__ == "__main__":
  unittest.main()
