import unittest
from pathlib import Path

from opendbc.car.secoc import add_mac28_zero_marker


ROOT = Path(__file__).resolve().parents[2]
PANDA_FDCAN = ROOT / "panda" / "board" / "drivers" / "fdcan.h"
TOYOTA_SAFETY = ROOT / "opendbc_repo" / "opendbc" / "safety" / "modes" / "toyota.h"
TOYOTA_CONTROLLER = ROOT / "opendbc_repo" / "opendbc" / "car" / "toyota" / "carcontroller.py"
CARD = ROOT / "openpilot" / "selfdrive" / "car" / "card.py"
PARAM_KEYS = ROOT / "openpilot" / "common" / "params_keys.h"
TSK_SERVER = ROOT / "tsk" / "web" / "server.py"
TSK_RUNTIME = ROOT / "tsk" / "lib" / "ephemeral_runtime.py"


class TestEphemeralSecocBridgeIntegration(unittest.TestCase):
  def test_zero_mac_marker_preserves_payload_and_transmitted_freshness_nibble(self):
    source = (0x2E4, bytes.fromhex("12345678aabbccdd"), 0)
    marked = add_mac28_zero_marker(reset_cnt=0x1235, msg_cnt=0xA6, msg=source)
    self.assertEqual(marked[0], 0x2E4)
    self.assertEqual(marked[2], 0)
    self.assertEqual(marked[1][:4], source[1][:4])
    expected_flags = (((0xA6 & 3) << 2) | (0x1235 & 3)) << 4
    self.assertEqual(marked[1][4], expected_flags)
    self.assertEqual(marked[1][4] & 0x0F, 0)
    self.assertEqual(marked[1][5:], b"\x00\x00\x00")

  def test_old_panda_forwarded_stock_mac_mutation_is_removed(self):
    source = PANDA_FDCAN.read_text(encoding="utf-8")
    self.assertNotIn("One-off Toyota SecOC Gate-2 ablation", source)
    self.assertNotIn("to_send.data[4] &= 0xF0U", source)
    self.assertNotIn("(to_send.addr == 0x2E4U) || (to_send.addr == 0x131U)", source)

  def test_stock_conflicting_secoc_frames_return_to_static_blocking(self):
    source = TOYOTA_SAFETY.read_text(encoding="utf-8")
    secoc = source[source.index("#define TOYOTA_COMMON_SECOC_TX_MSGS"):source.index("#define TOYOTA_COMMON_LONG_TX_MSGS")]
    self.assertIn("TOYOTA_BASE_TX_MSGS", secoc)
    self.assertIn("{0x2E4, 0, 8, .check_relay = true}", secoc)
    self.assertIn("{0x131, 0, 8, .check_relay = true}", secoc)
    self.assertNotIn("disable_static_blocking", secoc)
    self.assertNotIn("TOYOTA_SECOC_BASE_TX_MSGS", source)

  def test_controller_marks_only_secured_lateral_commands_when_bridge_is_explicitly_armed(self):
    source = TOYOTA_CONTROLLER.read_text(encoding="utf-8")
    self.assertIn("self.ephemeral_secoc_bridge = False", source)
    self.assertEqual(source.count("add_mac28_zero_marker("), 2)  # LKA and LTA calls only
    self.assertNotIn("stock_camera_ablation_addrs", source)
    self.assertNotIn("can_sends = [msg for msg in can_sends if msg[0] not in", source)

    lka = source[source.index("steer_command = toyotacan.create_steer_command"):source.index("can_sends.append(steer_command)")]
    self.assertIn("if self.ephemeral_secoc_bridge", lka)
    self.assertIn("add_mac28_zero_marker", lka)
    self.assertIn("add_mac(self.secoc_key", lka)

    lta = source[source.index("lta_steer_2 = toyotacan.create_lta_steer_command_2"):source.index("can_sends.append(lta_steer_2)")]
    self.assertIn("if self.ephemeral_secoc_bridge", lta)
    self.assertIn("add_mac28_zero_marker", lta)

    acc = source[source.index("acc_cmd_2 = toyotacan.create_accel_command"):source.index("self.secoc_acc_message_counter += 1")]
    self.assertIn("add_mac(self.secoc_key", acc)
    self.assertNotIn("add_mac28_zero_marker", acc)

  def test_openpilot_bridge_arming_is_persistent_exact_f181_bound_and_key_preferred(self):
    params = PARAM_KEYS.read_text(encoding="utf-8")
    self.assertIn('{"ToyotaEphemeralSecOCBridge", {PERSISTENT, BOOL}}', params)
    self.assertIn('{"ToyotaEphemeralSecOCBridgeF181", {PERSISTENT, STRING}}', params)

    source = CARD.read_text(encoding="utf-8")
    self.assertIn('bridge_requested = self.params.get_bool("ToyotaEphemeralSecOCBridge")', source)
    self.assertIn('bridge_f181_raw = self.params.get("ToyotaEphemeralSecOCBridgeF181")', source)
    self.assertIn('len(bridge_f181) == 13', source)
    self.assertIn('bridge_f181.startswith("8965")', source)
    self.assertIn('bridge_f181.isalnum()', source)
    self.assertIn("fw.ecu == structs.CarParams.Ecu.eps", source)
    self.assertIn("bridge_f181_valid and any(bridge_f181.encode() in fw for fw in eps_versions)", source)
    self.assertIn("if bridge_requested and not key_loaded", source)
    self.assertIn("elif self.CP.openpilotLongitudinalControl", source)
    self.assertIn("self.CI.CC.ephemeral_secoc_bridge = True", source)
    self.assertIn("self.CP.secOcKeyAvailable = True", source)

  def test_tsk_does_not_arm_or_deploy_the_resident_bridge(self):
    operational_source = "\n".join((
      TSK_SERVER.read_text(encoding="utf-8"),
      TSK_RUNTIME.read_text(encoding="utf-8"),
    ))
    self.assertNotIn("ToyotaEphemeralSecOCBridge", operational_source)
    self.assertNotIn("ToyotaEphemeralSecOCBridgeF181", operational_source)
    self.assertNotIn("ephemeral_secoc_runtime.bin", operational_source)
    self.assertNotIn("bridge-deployment", operational_source)


if __name__ == "__main__":
  unittest.main()
