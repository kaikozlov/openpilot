import unittest

from tools.toyota_diag import recorder


class TestTss3Recorder(unittest.TestCase):
  def test_level49_vectors_match_current_gtsplus(self):
    vectors = {
      "000000000000": "000000000000",
      "010203040506": "04070a0d1a64",
      "123456789abc": "9e6a50252409",
      "deadbeefcafe": "cbd8b6970cba",
      "690f82163710": "e1ff8791db01",  # exact 2026 Camry live seed/key
    }
    for seed, expected in vectors.items():
      with self.subTest(seed=seed):
        self.assertEqual(recorder.level49_key(bytes.fromhex(seed)).hex(), expected)

  def test_operation_enumeration_and_record_decode(self):
    self.assertEqual(recorder.parse_operation_behaviors(bytes.fromhex("eb1128182845")), [0x2818, 0x2845])
    self.assertEqual(recorder.parse_operation_records(bytes.fromhex("eb122818010101000101"), 0x2818), [0x0100, 0x0101])

    # Counted EB13 form observed live on the exact Camry.  523D exercises
    # big-endian IEEE float decode; 5631 exercises signed fixed-point decode.
    response = bytes.fromhex("eb132818010002523d04c040000056310500ffc76400")
    decoded = recorder.decode_operation_record(recorder.parse_operation_record(response, 0x2818, 0x0100))
    steering = next(block for block in decoded["blocks"] if block["data_id"] == 0x523D)
    lta = next(block for block in decoded["blocks"] if block["data_id"] == 0x5631)
    self.assertEqual(steering["signals"][0]["formatted"], "-3.000")
    self.assertEqual([signal["formatted"] for signal in lta["signals"]], ["0", "-0.057", "1.00", "0.00"])

  def test_operation_parser_uses_literal_length_and_count(self):
    # The retained 2818/0100 live specimen parses literally: its 568D block is
    # length 30 and the outer count determines the complete block set.
    response = bytes.fromhex("eb132818010002568d1e" + "00" * 30 + "5631050000000000")
    parsed = recorder.parse_operation_record(response, 0x2818, 0x0100)
    self.assertEqual(parsed["block_count"], 2)
    self.assertEqual([(block["data_id"], block["length"]) for block in parsed["blocks"]], [(0x568D, 30), (0x5631, 5)])

  def test_image_split_record_parser(self):
    response = bytes.fromhex("eb3328220000020102050102aabb600200000003112233")
    record = recorder.parse_image_record(response, 0x2822, 0x201)
    self.assertEqual(record["block_count"], 2)
    self.assertEqual([(block["data_id"], block["length"], block["data"].hex()) for block in record["blocks"]], [
      (0x0501, 2, "aabb"), (0x6002, 3, "112233"),
    ])
    self.assertEqual(recorder.image_frame_occurrence(1, 1, 1), 0x201)

  def test_recorder_dictionary_contains_lateral_arbitration_oracles(self):
    names = {row["DataName"] for _, row in recorder.search_signals("pinion angle")}
    self.assertIn("TSS request - pinion angle", names)
    self.assertIn("LTA Control Request Pinion Angle", names)
    self.assertIn("Arbitration result Pinion angle", names)
    self.assertEqual(recorder.rob_row(0x2845)["DataName"], "LTA Hands Free Cancel")


if __name__ == "__main__":
  unittest.main()
