import unittest
from unittest.mock import Mock, patch

from tsk.lib.extractor import RetryError, TSKExtractor


class TestExtractorGeometryGate(unittest.TestCase):
  def test_unknown_f181_fails_before_programming_handoff(self):
    route = {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 1, "elm327_param": 1, "semantic_path": "normal-harness"}
    app_uds = Mock()
    app_uds.read_data_by_identifier.return_value = b"\x018965F1208999\x00\x00\x00\x00"

    with patch("tsk.lib.extractor.is_agnos", return_value=True), \
         patch("tsk.lib.extractor.subprocess.run"), \
         patch("tsk.lib.extractor.time.sleep"), \
         patch("tsk.lib.extractor.TSKExtractor._connect_panda", return_value=Mock()), \
         patch("tsk.lib.extractor.discover_eps_route_with_routing", return_value=route), \
         patch("tsk.lib.extractor.make_uds_client", return_value=app_uds), \
         patch("tsk.lib.extractor.enter_programming_bootloader") as handoff:
      with self.assertRaisesRegex(RetryError, "Refusing RAM extraction before PROGRAMMING"):
        TSKExtractor.hack()
      handoff.assert_not_called()
      self.assertFalse(TSKExtractor._last_extraction_metadata["known_application"])
      self.assertEqual(TSKExtractor._last_extraction_metadata["ram_exec_geometry"]["status"], "unverified")

  def test_4512000_geometry_does_not_enable_legacy_ram_key_table_extractor(self):
    route = {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 1, "elm327_param": 1, "semantic_path": "normal-harness"}
    app_uds = Mock()
    app_uds.read_data_by_identifier.return_value = b"\x018965B4512000\x00\x00\x00\x00"

    with patch("tsk.lib.extractor.is_agnos", return_value=True), \
         patch("tsk.lib.extractor.subprocess.run"), \
         patch("tsk.lib.extractor.time.sleep"), \
         patch("tsk.lib.extractor.TSKExtractor._connect_panda", return_value=Mock()), \
         patch("tsk.lib.extractor.discover_eps_route_with_routing", return_value=route), \
         patch("tsk.lib.extractor.make_uds_client", return_value=app_uds), \
         patch("tsk.lib.extractor.enter_programming_bootloader") as handoff:
      with self.assertRaisesRegex(RetryError, "legacy RAM key-table layout"):
        TSKExtractor.hack()
      handoff.assert_not_called()
      self.assertEqual(TSKExtractor._last_extraction_metadata["ram_exec_geometry"]["status"], "verified")

  def test_field_supported_geometry_without_exact_fixture_fails_before_programming(self):
    route = {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 1, "elm327_param": 1, "semantic_path": "normal-harness"}
    app_uds = Mock()
    app_uds.read_data_by_identifier.return_value = b"\x018965B4509100\x00\x00\x00\x00"

    with patch("tsk.lib.extractor.is_agnos", return_value=True), \
         patch("tsk.lib.extractor.subprocess.run"), \
         patch("tsk.lib.extractor.time.sleep"), \
         patch("tsk.lib.extractor.TSKExtractor._connect_panda", return_value=Mock()), \
         patch("tsk.lib.extractor.discover_eps_route_with_routing", return_value=route), \
         patch("tsk.lib.extractor.make_uds_client", return_value=app_uds), \
         patch("tsk.lib.extractor.enter_programming_bootloader") as handoff:
      with self.assertRaisesRegex(RetryError, "exact payload fixture is not target-evidenced"):
        TSKExtractor.hack()
      handoff.assert_not_called()
      self.assertTrue(TSKExtractor._last_extraction_metadata["known_application"])
      self.assertEqual(TSKExtractor._last_extraction_metadata["ram_exec_geometry"]["status"], "verified")


if __name__ == "__main__":
  unittest.main()
