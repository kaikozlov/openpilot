import random
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PANDA_FDCAN = ROOT / "panda" / "board" / "drivers" / "fdcan.h"
TOYOTA_SAFETY = ROOT / "opendbc_repo" / "opendbc" / "safety" / "modes" / "toyota.h"
TOYOTA_CONTROLLER = ROOT / "opendbc_repo" / "opendbc" / "car" / "toyota" / "carcontroller.py"

PROTECTED_IDS = {0x2E4, 0x131}
STOCK_CAMERA_IDS = {0x191, 0x412, 0x2E4, 0x131}


def invalidate_mac28(data: bytes) -> bytes:
  if len(data) != 8:
    raise ValueError("classic Toyota SecOC frame must be exactly 8 bytes")
  result = bytearray(data)
  result[4] &= 0xF0
  result[5:8] = b"\x00\x00\x00"
  return bytes(result)


class TestMac28Ablation(unittest.TestCase):
  def test_mac28_transform_changes_only_authenticator_bits(self):
    rng = random.Random(0x28)
    for _ in range(128):
      source = bytes(rng.randrange(256) for _ in range(8))
      result = invalidate_mac28(source)
      self.assertEqual(result[:4], source[:4])
      self.assertEqual(result[4] & 0xF0, source[4] & 0xF0)
      self.assertEqual(result[4] & 0x0F, 0)
      self.assertEqual(result[5:], b"\x00\x00\x00")

  def test_panda_mutates_only_stock_camera_direction_before_packet_checksum(self):
    source = PANDA_FDCAN.read_text(encoding="utf-8")
    copy_at = source.index("(void)memcpy(to_send.data, to_push.data")
    guard_at = source.index("(bus_number == 2U) && (bus_fwd_num == 0)", copy_at)
    mask_at = source.index("to_send.data[4] &= 0xF0U;", guard_at)
    checksum_at = source.index("can_set_checksum(&to_send);", mask_at)
    self.assertLess(copy_at, guard_at)
    self.assertLess(guard_at, mask_at)
    self.assertLess(mask_at, checksum_at)
    self.assertIn("(to_send.addr == 0x2E4U) || (to_send.addr == 0x131U)", source[guard_at:mask_at])
    self.assertIn("dlc_to_len[to_send.data_len_code] == 8U", source[guard_at:mask_at])
    self.assertIn("to_send.data[5] = 0U;", source[mask_at:checksum_at])
    self.assertIn("to_send.data[6] = 0U;", source[mask_at:checksum_at])
    self.assertIn("to_send.data[7] = 0U;", source[mask_at:checksum_at])

  def test_toyota_static_blocking_override_is_exact_four_id_scope(self):
    source = TOYOTA_SAFETY.read_text(encoding="utf-8")
    entries = re.findall(r"\{([^{}]+)\}", source)
    enabled_entries = {
      int(match.group(1), 16)
      for entry in entries
      if ".disable_static_blocking = true" in entry
      if (match := re.match(r"\s*(0x[0-9A-Fa-f]+)\s*,", entry)) is not None
    }
    self.assertEqual(enabled_entries, STOCK_CAMERA_IDS)
    self.assertIn("{0x2E4, 0, 5, .check_relay = true}", source)

  def test_controller_suppresses_exact_four_ids_only_on_secoc_targets(self):
    source = TOYOTA_CONTROLLER.read_text(encoding="utf-8")
    guard = "if self.CP.flags & ToyotaFlags.SECOC.value:"
    set_literal = "stock_camera_ablation_addrs = {0x191, 0x412, 0x2E4, 0x131}"
    filter_line = "can_sends = [msg for msg in can_sends if msg[0] not in stock_camera_ablation_addrs]"
    guard_at = source.rindex(guard)
    set_at = source.index(set_literal, guard_at)
    filter_at = source.index(filter_line, set_at)
    self.assertLess(guard_at, set_at)
    self.assertLess(set_at, filter_at)
    parsed = {int(value, 16) for value in ("0x191", "0x412", "0x2E4", "0x131")}
    self.assertEqual(parsed, STOCK_CAMERA_IDS)


if __name__ == "__main__":
  unittest.main()
