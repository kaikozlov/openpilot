import unittest
from unittest.mock import Mock, patch

from opendbc.car.uds import NegativeResponseError

from tsk.lib.dump_diag import diagnose


class TestDumpDiagnosticRiskBoundary(unittest.TestCase):
  ROUTE = {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 1, "elm327_param": 1, "semantic_path": "normal-harness"}

  @staticmethod
  def _app_uds(f181: bytes) -> Mock:
    uds = Mock()

    def read_did(did):
      if did == 0xF181:
        return f181
      return b"fixture"

    uds.read_data_by_identifier.side_effect = read_did
    return uds

  @staticmethod
  def _boot_uds() -> Mock:
    uds = Mock()

    def read_did(did):
      if did == 0xF181:
        return b"\x01BOOTLOADER-UNKNOWN"
      if did == 0xF180:
        return b"BOOT-SW"
      return b"BOOT-PART"

    uds.read_data_by_identifier.side_effect = read_did
    uds.security_access.return_value = b"\x11" * 16
    return uds

  def _run_unknown(self, *, armed: bool = False):
    panda = Mock()
    panda.get_version.return_value = b"test"
    app_uds = self._app_uds(b"\x018965F1208000\x00\x00\x00\x00")
    boot_uds = self._boot_uds()

    with patch("tsk.lib.dump_diag.is_agnos", return_value=True), \
         patch("tsk.lib.dump_diag.subprocess.run"), \
         patch("tsk.lib.dump_diag.time.sleep"), \
         patch("tsk.lib.dump_diag.TSKExtractor._connect_panda", return_value=panda), \
         patch("tsk.lib.dump_diag.discover_eps_route_with_routing", return_value=self.ROUTE), \
         patch("tsk.lib.dump_diag.uds_client", side_effect=[app_uds, boot_uds]), \
         patch("tsk.lib.dump_diag.enter_programming_bootloader",
               return_value=(self.ROUTE, {"programming_response_timeout": True})) as handoff:
      result = diagnose(allow_cross_calibration_send_key=armed)

    return result, app_uds, boot_uds, handoff

  def test_unknown_f181_observes_handoff_bootloader_identity_and_seed_before_stopping(self):
    result, app_uds, boot_uds, handoff = self._run_unknown()

    self.assertEqual(result["status"], "observed")
    self.assertEqual(result["ram_exec_geometry"]["status"], "unverified")
    self.assertEqual(result["security_seed"], (b"\x11" * 16).hex())
    self.assertEqual(len(result["bootloader_identity"]), 3)
    self.assertIn("counted attempt", result["message"])
    self.assertIn("No WDBI", result["message"])
    handoff.assert_called_once()
    app_uds.diagnostic_session_control.assert_called_once()
    self.assertEqual(boot_uds.security_access.call_count, 1)  # REQUEST_SEED only
    boot_uds.write_data_by_identifier.assert_not_called()
    boot_uds._uds_request.assert_not_called()

  def test_unknown_f181_can_explicitly_spend_one_bootloader_send_key_attempt_without_payload(self):
    result, _app_uds, boot_uds, handoff = self._run_unknown(armed=True)

    self.assertEqual(result["status"], "observed")
    self.assertTrue(result["send_key_armed"])
    self.assertTrue(result["cross_calibration_send_key"])
    self.assertEqual(boot_uds.security_access.call_count, 2)  # REQUEST_SEED + SEND_KEY
    self.assertIn("explicitly armed", result["message"])
    self.assertIn("RAM-exec geometry is still unknown", result["message"])
    handoff.assert_called_once()
    boot_uds.write_data_by_identifier.assert_not_called()
    boot_uds._uds_request.assert_not_called()

  def test_armed_cross_calibration_key_rejection_is_an_observation_not_a_tool_failure(self):
    panda = Mock()
    panda.get_version.return_value = b"test"
    app_uds = self._app_uds(b"\x018965F1208000\x00\x00\x00\x00")
    boot_uds = self._boot_uds()
    boot_uds.security_access.side_effect = [
      b"\x11" * 16,
      NegativeResponseError("invalid key", 0x27, 0x35),
    ]

    with patch("tsk.lib.dump_diag.is_agnos", return_value=True), \
         patch("tsk.lib.dump_diag.subprocess.run"), \
         patch("tsk.lib.dump_diag.time.sleep"), \
         patch("tsk.lib.dump_diag.TSKExtractor._connect_panda", return_value=panda), \
         patch("tsk.lib.dump_diag.discover_eps_route_with_routing", return_value=self.ROUTE), \
         patch("tsk.lib.dump_diag.uds_client", side_effect=[app_uds, boot_uds]), \
         patch("tsk.lib.dump_diag.enter_programming_bootloader",
               return_value=(self.ROUTE, {"programming_response_timeout": True})):
      result = diagnose(allow_cross_calibration_send_key=True)

    self.assertEqual(result["status"], "observed")
    self.assertIn("NRC 0x35", result["send_key_result"])
    self.assertFalse(result["failed_at"])
    self.assertIn("counted comparison is complete", result["message"])
    boot_uds.write_data_by_identifier.assert_not_called()
    boot_uds._uds_request.assert_not_called()



if __name__ == "__main__":
  unittest.main()
