import unittest
from unittest.mock import Mock, patch

from tsk.lib.dump_diag import diagnose


class TestDumpDiagnosticGeometryGate(unittest.TestCase):
  def test_unknown_f181_stops_after_identity_before_programming(self):
    route = {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 1, "elm327_param": 1, "semantic_path": "normal-harness"}
    panda = Mock()
    panda.get_version.return_value = b"test"
    uds = Mock()

    def read_did(did):
      if did == 0xF181:
        return b"\x018965F1208000\x00\x00\x00\x00"
      return b"fixture"

    uds.read_data_by_identifier.side_effect = read_did

    with patch("tsk.lib.dump_diag.is_agnos", return_value=True), \
         patch("tsk.lib.dump_diag.subprocess.run"), \
         patch("tsk.lib.dump_diag.time.sleep"), \
         patch("tsk.lib.dump_diag.TSKExtractor._connect_panda", return_value=panda), \
         patch("tsk.lib.dump_diag.discover_eps_route_with_routing", return_value=route), \
         patch("tsk.lib.dump_diag.uds_client", return_value=uds), \
         patch("tsk.lib.dump_diag.enter_programming_bootloader") as handoff:
      result = diagnose()

    self.assertEqual(result["status"], "rejected")
    self.assertEqual(result["ram_exec_geometry"]["status"], "unverified")
    self.assertIn("no PROGRAMMING request was sent", result["message"])
    self.assertEqual(result["steps"][-1]["name"], "RAM-exec geometry")
    uds.diagnostic_session_control.assert_not_called()
    handoff.assert_not_called()


if __name__ == "__main__":
  unittest.main()
