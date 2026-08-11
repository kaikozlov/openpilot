import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tsk.lib.dump_dataflash import DUMP_TOTAL, _finalize


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
