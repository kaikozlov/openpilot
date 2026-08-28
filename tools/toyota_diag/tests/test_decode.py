import unittest

from tools.toyota_diag import decode, registry


class TestDecode(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.profile = registry.load_registry()

  def test_cross_byte_msb0_extraction(self):
    self.assertEqual(decode.extract_msb0(bytes.fromhex("a53c"), 4, 11), 0x53)

  def test_signed_division_truncates_toward_zero(self):
    self.assertEqual(
      decode.convert_p5_physical(0xFF, bit_width=8, signed=True, mul=5, div=2, offset=0),
      -2,
    )

  def test_decimal_rendering_is_exact(self):
    self.assertEqual(decode.format_p5_decimal(-15, 1), "-1.5")
    self.assertEqual(decode.format_p5_decimal(15, 3), "0.015")

  def test_eps_steering_angle_witness(self):
    _, signals = self.profile.resolve_did("eps", "0x1037")
    self.assertEqual(len(signals), 1)
    self.assertEqual(
      decode.decode_signal(bytes.fromhex("0001"), signals[0]),
      {"raw": 1, "converted_integer": 15, "value": "1.5", "pattern": None},
    )
    self.assertEqual(decode.format_decoded_signal(bytes.fromhex("0001"), signals[0]),
                     "Steering Angle: 1.5 deg (raw=0x0001)")

  def test_frc_pattern_witness(self):
    _, signals = self.profile.resolve_did("frc", "0x1601")
    condition = next(row for row in signals if row["name"] == "LTA Control Condition")
    self.assertEqual(
      decode.format_decoded_signal(bytes.fromhex("00010000"), condition),
      "LTA Control Condition: LTA Disabled (raw=0x01)",
    )

  def test_unknown_decoder_and_short_payload_fail_closed(self):
    with self.assertRaisesRegex(decode.DecodeError, "unsupported decoder"):
      decode.decode_signal(b"\x00", {"decoder": "unknown"})
    _, signals = self.profile.resolve_did("eps", "0x1037")
    with self.assertRaisesRegex(decode.DecodeError, "exceed 1-byte DID payload"):
      decode.decode_signal(b"\x00", signals[0])


if __name__ == "__main__":
  unittest.main()
