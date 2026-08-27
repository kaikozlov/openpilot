import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tsk.lib.bootstrap_profile import CODEFLASH_FIXTURE_SHA256, fixture_is_evidenced
from tsk.lib.camry_f33 import CAMRY_F33_APP_F181, CAMRY_F33_ROUTE
from tsk.lib.dump_codeflash import (
  DUMP_END, DUMP_START, DUMP_TOTAL, EXPECTED_NORMALIZED_SHA256, EXPECTED_RAW_SHA256,
  EXPECTED_WORDS, NORMALIZED_SIZE, PAYLOAD_SHA256, _decode_dump_frame, _exact_route,
  _integrity, _load_resume, dump,
)
from tsk.lib.extractor import RetryError


def response_frame(address: int, word: bytes) -> tuple[int, bytes, int]:
  header = ((address & 0xFFFFFF) << 8) | 0x07
  return int(CAMRY_F33_ROUTE["rx"]), header.to_bytes(4, "little") + word, int(CAMRY_F33_ROUTE["rx_bus"])


class TestCamryCodeFlashPureHelpers(unittest.TestCase):
  def test_payload_fixture_is_exact_camry_evidence(self):
    self.assertEqual(PAYLOAD_SHA256, CODEFLASH_FIXTURE_SHA256)
    self.assertTrue(fixture_is_evidenced(CAMRY_F33_APP_F181, PAYLOAD_SHA256))
    self.assertFalse(fixture_is_evidenced("8965F3401200", PAYLOAD_SHA256))

  def test_route_is_exact_not_family_wide(self):
    self.assertTrue(_exact_route(dict(CAMRY_F33_ROUTE)))
    for key, wrong in (("tx_bus", 0), ("rx", 0x7AA), ("elm327_param", 0)):
      route = dict(CAMRY_F33_ROUTE)
      route[key] = wrong
      self.assertFalse(_exact_route(route), key)

  def test_dump_frame_decoder_bounds_and_alignment(self):
    self.assertEqual(_decode_dump_frame(*response_frame(0, b"ABCD")), (0, b"ABCD"))
    self.assertEqual(_decode_dump_frame(*response_frame(DUMP_END - 4, b"WXYZ")), (EXPECTED_WORDS - 1, b"WXYZ"))
    self.assertIsNone(_decode_dump_frame(*response_frame(DUMP_END, b"nope")))
    self.assertIsNone(_decode_dump_frame(*response_frame(2, b"nope")))
    self.assertIsNone(_decode_dump_frame(0x7A8, response_frame(0, b"ABCD")[1], 1))

  def test_resume_requires_exact_sizes_and_binary_coverage(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      raw = root / "raw.bin"
      coverage = root / "coverage.bin"
      raw.write_bytes(bytes(DUMP_TOTAL))
      mask = bytearray(EXPECTED_WORDS)
      mask[0] = 1
      coverage.write_bytes(mask)
      image, seen = _load_resume(raw, coverage)
      self.assertEqual(len(image), DUMP_TOTAL)
      self.assertEqual(sum(seen), 1)
      coverage.write_bytes(bytes([2]) + bytes(EXPECTED_WORDS - 1))
      with self.assertRaisesRegex(RetryError, "values other than 0/1"):
        _load_resume(raw, coverage)

  def test_integrity_matches_retained_complete_image_contract(self):
    # This helper is deterministic without bundling the 2 MiB evidence image in openpilot.
    incomplete = _integrity(bytes(DUMP_TOTAL), bytes(EXPECTED_WORDS))
    self.assertFalse(incomplete["complete"])
    self.assertEqual(EXPECTED_RAW_SHA256,
                     "b588c7258699beee77669d1f5f09bb17ef8b189b941b46f344a07378c3aaa727")
    self.assertEqual(EXPECTED_NORMALIZED_SHA256,
                     "42dce8efc42f6ae31718e7713fa2d26bb9191b4a82439778aee4d7afded9b0e7")
    self.assertEqual(NORMALIZED_SIZE, 0x100000)
    self.assertEqual((DUMP_START, DUMP_END), (0, 0x200000))


class TestCamryCodeFlashLiveGuards(unittest.TestCase):
  def _base(self, f181: bytes, ready: int):
    panda = Mock()
    panda.can_recv.return_value = [(0x51E, bytes([ready << 7]) + bytes(7), 1)]
    app = Mock()
    app.read_data_by_identifier.return_value = f181
    return panda, app

  def test_wrong_application_identity_stops_before_programming(self):
    panda, app = self._base(b"\x018965F3307001\x00\x00\x00\x00", 0)
    with tempfile.TemporaryDirectory() as directory, \
         patch("tsk.lib.dump_codeflash.is_agnos", return_value=True), \
         patch("tsk.lib.dump_codeflash.subprocess.run"), \
         patch("tsk.lib.dump_codeflash.time.sleep"), \
         patch("tsk.lib.dump_codeflash.TSKExtractor._connect_panda", return_value=panda), \
         patch("tsk.lib.dump_codeflash.discover_eps_route_with_routing", return_value=dict(CAMRY_F33_ROUTE)), \
         patch("tsk.lib.dump_codeflash.uds_client", return_value=app), \
         patch("tsk.lib.dump_codeflash.enter_programming_bootloader") as handoff:
      with self.assertRaisesRegex(RetryError, "unexpected application F181"):
        dump(output_dir=Path(directory))
      handoff.assert_not_called()

  def test_ready_vehicle_stops_before_programming(self):
    panda, app = self._base(CAMRY_F33_APP_F181, 1)
    with tempfile.TemporaryDirectory() as directory, \
         patch("tsk.lib.dump_codeflash.is_agnos", return_value=True), \
         patch("tsk.lib.dump_codeflash.subprocess.run"), \
         patch("tsk.lib.dump_codeflash.time.sleep"), \
         patch("tsk.lib.dump_codeflash.TSKExtractor._connect_panda", return_value=panda), \
         patch("tsk.lib.dump_codeflash.discover_eps_route_with_routing", return_value=dict(CAMRY_F33_ROUTE)), \
         patch("tsk.lib.dump_codeflash.uds_client", return_value=app), \
         patch("tsk.lib.dump_codeflash.enter_programming_bootloader") as handoff:
      with self.assertRaisesRegex(RetryError, "vehicle is READY"):
        dump(output_dir=Path(directory))
      handoff.assert_not_called()


if __name__ == "__main__":
  unittest.main()
