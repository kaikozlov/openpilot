import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tsk.lib.dump_dataflash import DUMP_TOTAL, _finalize, dump
from tsk.lib.extractor import RetryError
from tsk.lib.programming import ProgrammingHandoffError


class TestDataFlashGeometryGate(unittest.TestCase):
  def test_unknown_f181_fails_before_programming_handoff(self):
    route = {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 1, "elm327_param": 1, "semantic_path": "normal-harness"}
    app_uds = Mock()
    app_uds.read_data_by_identifier.return_value = b"\x018965F9999999\x00\x00\x00\x00"

    with patch("tsk.lib.dump_dataflash.is_agnos", return_value=True), \
         patch("tsk.lib.dump_dataflash.subprocess.run"), \
         patch("tsk.lib.dump_dataflash.time.sleep"), \
         patch("tsk.lib.dump_dataflash.TSKExtractor._connect_panda", return_value=Mock()), \
         patch("tsk.lib.dump_dataflash.discover_eps_route_with_routing", return_value=route), \
         patch("tsk.lib.dump_dataflash.uds_client", return_value=app_uds), \
         patch("tsk.lib.dump_dataflash.enter_programming_bootloader") as handoff:
      with self.assertRaisesRegex(RetryError, "Refusing DataFlash payload before PROGRAMMING"):
        dump()
      handoff.assert_not_called()

  def test_geometry_compatible_target_without_exact_dataflash_fixture_stops_before_programming(self):
    route = {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 1, "elm327_param": 1, "semantic_path": "normal-harness"}
    app_uds = Mock()
    app_uds.read_data_by_identifier.return_value = b"\x018965B4509100\x00\x00\x00\x00"

    with patch("tsk.lib.dump_dataflash.is_agnos", return_value=True), \
         patch("tsk.lib.dump_dataflash.subprocess.run"), \
         patch("tsk.lib.dump_dataflash.time.sleep"), \
         patch("tsk.lib.dump_dataflash.TSKExtractor._connect_panda", return_value=Mock()), \
         patch("tsk.lib.dump_dataflash.discover_eps_route_with_routing", return_value=route), \
         patch("tsk.lib.dump_dataflash.uds_client", return_value=app_uds), \
         patch("tsk.lib.dump_dataflash.enter_programming_bootloader") as handoff:
      with self.assertRaisesRegex(RetryError, "exact encrypted-fixture acceptance"):
        dump()
      handoff.assert_not_called()

  def test_4512000_exact_dataflash_fixture_reaches_programming_handoff(self):
    route = {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 1, "elm327_param": 1, "semantic_path": "normal-harness"}
    app_uds = Mock()
    app_uds.read_data_by_identifier.return_value = b"\x018965B4512000\x00\x00\x00\x00"

    with patch("tsk.lib.dump_dataflash.is_agnos", return_value=True), \
         patch("tsk.lib.dump_dataflash.subprocess.run"), \
         patch("tsk.lib.dump_dataflash.time.sleep"), \
         patch("tsk.lib.dump_dataflash.TSKExtractor._connect_panda", return_value=Mock()), \
         patch("tsk.lib.dump_dataflash.discover_eps_route_with_routing", return_value=route), \
         patch("tsk.lib.dump_dataflash.uds_client", return_value=app_uds), \
         patch("tsk.lib.dump_dataflash.enter_programming_bootloader",
               side_effect=ProgrammingHandoffError("stop after fixture gates")) as handoff:
      with self.assertRaisesRegex(RetryError, "Can't enter programming bootloader"):
        dump()
      handoff.assert_called_once()

  def test_camry_two_record_f181_standard_fixture_reaches_programming_handoff(self):
    route = {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 1, "elm327_param": 1, "semantic_path": "normal-harness"}
    app_uds = Mock()
    app_uds.read_data_by_identifier.return_value = (
      b"\x02" + b"8965F3307000\x00\x00\x00\x00" + b"8A3113303100\x00\x00\x00\x00"
    )

    with patch("tsk.lib.dump_dataflash.is_agnos", return_value=True), \
         patch("tsk.lib.dump_dataflash.subprocess.run"), \
         patch("tsk.lib.dump_dataflash.time.sleep"), \
         patch("tsk.lib.dump_dataflash.TSKExtractor._connect_panda", return_value=Mock()), \
         patch("tsk.lib.dump_dataflash.discover_eps_route_with_routing", return_value=route), \
         patch("tsk.lib.dump_dataflash.uds_client", return_value=app_uds), \
         patch("tsk.lib.dump_dataflash.enter_programming_bootloader",
               side_effect=ProgrammingHandoffError("stop after fixture gates")) as handoff:
      with self.assertRaisesRegex(RetryError, "Can't enter programming bootloader"):
        dump()
      handoff.assert_called_once()

  def test_camry_autoreset_fixture_remains_blocked_before_programming(self):
    route = {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 1, "elm327_param": 1, "semantic_path": "normal-harness"}
    app_uds = Mock()
    app_uds.read_data_by_identifier.return_value = (
      b"\x02" + b"8965F3307000\x00\x00\x00\x00" + b"8A3113303100\x00\x00\x00\x00"
    )

    with patch("tsk.lib.dump_dataflash.is_agnos", return_value=True), \
         patch("tsk.lib.dump_dataflash.subprocess.run"), \
         patch("tsk.lib.dump_dataflash.time.sleep"), \
         patch("tsk.lib.dump_dataflash.TSKExtractor._connect_panda", return_value=Mock()), \
         patch("tsk.lib.dump_dataflash.discover_eps_route_with_routing", return_value=route), \
         patch("tsk.lib.dump_dataflash.uds_client", return_value=app_uds), \
         patch("tsk.lib.dump_dataflash.enter_programming_bootloader") as handoff:
      with self.assertRaisesRegex(RetryError, "exact encrypted-fixture acceptance"):
        dump(auto_reset=True)
      handoff.assert_not_called()


class TestDataFlashFinalize(unittest.TestCase):
  def test_partial_is_not_gated_on_historical_6e14_window(self):
    dump_buf = bytearray(DUMP_TOTAL)
    received = bytearray(DUMP_TOTAL)
    offset = 0x120
    dump_buf[offset:offset + 16] = bytes(range(16))
    received[offset:offset + 16] = b"\x01" * 16

    with tempfile.TemporaryDirectory() as directory:
      complete = Path(directory) / "dump.bin"
      with patch("tsk.lib.dump_dataflash.dump_path", return_value=complete):
        result = _finalize(dump_buf, received, frames_count=4, bytes_received=16)
        partial = Path(result["dump_path"])
        coverage = Path(result["coverage_path"])
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["known_key_window_covered"])
        self.assertEqual(result["longest_covered_run"], 16)
        self.assertTrue(partial.is_file())
        mask = coverage.read_bytes()
        self.assertEqual(len(mask), DUMP_TOTAL)
        self.assertEqual(mask[offset:offset + 16], b"\x01" * 16)
        self.assertFalse(any(mask[:offset]))

  def test_partial_without_one_full_candidate_window_is_not_persisted(self):
    dump_buf = bytearray(DUMP_TOTAL)
    received = bytearray(DUMP_TOTAL)
    for offset in (0x100, 0x200, 0x300):
      received[offset:offset + 4] = b"\x01" * 4

    with tempfile.TemporaryDirectory() as directory:
      complete = Path(directory) / "dump.bin"
      with patch("tsk.lib.dump_dataflash.dump_path", return_value=complete):
        result = _finalize(dump_buf, received, frames_count=3, bytes_received=12)
        self.assertEqual(result["status"], "unusable_partial")
        self.assertEqual(result["longest_covered_run"], 4)
        self.assertEqual(result["dump_path"], "")
        self.assertFalse(Path(str(complete) + ".partial").exists())

  def test_complete_dump_removes_stale_partial_artifacts(self):
    dump_buf = bytearray((i & 0xFF) for i in range(DUMP_TOTAL))
    received = bytearray(b"\x01" * DUMP_TOTAL)

    with tempfile.TemporaryDirectory() as directory:
      complete = Path(directory) / "dump.bin"
      partial = Path(str(complete) + ".partial")
      coverage = Path(str(partial) + ".coverage")
      partial.write_bytes(b"stale")
      coverage.write_bytes(b"stale")
      with patch("tsk.lib.dump_dataflash.dump_path", return_value=complete):
        result = _finalize(dump_buf, received, frames_count=DUMP_TOTAL // 4,
                           bytes_received=DUMP_TOTAL)
      self.assertEqual(result["status"], "complete")
      self.assertEqual(complete.read_bytes(), bytes(dump_buf))
      self.assertFalse(partial.exists())
      self.assertFalse(coverage.exists())


if __name__ == "__main__":
  unittest.main()
