import unittest

from tsk.lib.matcher import (
  _aes_cmac, _cmac_subkeys, _first28, _freshness, _sync_input, find_key,
  verify_candidate_key,
)


class TestMatcher(unittest.TestCase):
  def _oracle(self, key: bytes, ids=(0x116, 0x24D), sync_key=None, sync_count=3):
    sync_key = key if sync_key is None else sync_key
    sync_subkeys = _cmac_subkeys(sync_key)
    protected_subkeys = _cmac_subkeys(key)
    sync = []
    for i in range(sync_count):
      trip, reset = 0x1001 + i, 0x23456 + i
      auth = _first28(_aes_cmac(sync_key, _sync_input(trip, reset), sync_subkeys))
      sync.append({"bus": 1, "trip": trip, "reset": reset, "auth": auth})

    protected = []
    trip, reset = sync[-1]["trip"], sync[-1]["reset"]
    for i in range(32):
      addr = ids[i % len(ids)]
      msg_cnt = i & 0xFF
      payload4 = bytes((i, i ^ 0x55, i ^ 0xAA, (i * 7) & 0xFF))
      flag = ((msg_cnt & 3) << 2) | (reset & 3)
      msg = addr.to_bytes(2, "big") + payload4 + _freshness(trip, reset, msg_cnt)
      auth = _first28(_aes_cmac(key, msg, protected_subkeys))
      protected.append({
        "addr": addr, "bus": 1, "payload4": payload4, "flag": flag,
        "auth": auth, "trip": trip, "reset": reset,
      })
    return sync, protected

  def test_candidate_verification_accepts_bus1_116_24d(self):
    key = bytes(range(16))
    sync, protected = self._oracle(key)
    result = verify_candidate_key(key, sync, protected)
    self.assertEqual(result["status"], "found")
    self.assertGreaterEqual(result["matches"], 30)
    self.assertEqual(result["protected_by_id"]["0x116"], 16)
    self.assertEqual(result["protected_by_id"]["0x24d"], 16)
    self.assertEqual(result["protected_by_bus"]["1"], 32)
    self.assertFalse(result["control_ready"])
    self.assertEqual(result["control_missing"], ["0x131", "0x2e4"])

  def test_candidate_control_domain_requires_131_and_2e4(self):
    key = bytes(range(16))
    sync, protected = self._oracle(key, ids=(0x131, 0x2E4))
    result = verify_candidate_key(key, sync, protected)
    self.assertEqual(result["status"], "found")
    self.assertTrue(result["control_ready"])
    self.assertEqual(result["control_matches_by_id"], {"0x131": 16, "0x2e4": 16})
    self.assertEqual(result["control_missing"], [])

  def test_current_openpilot_compatibility_reports_lateral_and_longitudinal_separately(self):
    key = bytes(range(16))
    sync, protected = self._oracle(key, ids=(0x131, 0x183, 0x2E4))
    result = verify_candidate_key(key, sync, protected)
    self.assertEqual(result["status"], "found")
    self.assertTrue(result["legacy_lateral_ready"])
    self.assertTrue(result["legacy_longitudinal_ready"])
    self.assertEqual(result["legacy_lateral_matches_by_id"], {"0x131": 11, "0x2e4": 10})
    self.assertEqual(result["legacy_longitudinal_matches_by_id"], {"0x183": 11})

  def test_protected_only_control_key_is_valid_with_separate_sync_key(self):
    key = bytes(range(16))
    sync_key = bytes(range(16, 32))
    sync, protected = self._oracle(key, ids=(0x131, 0x2E4), sync_key=sync_key)
    result = verify_candidate_key(key, sync, protected)
    self.assertEqual(result["status"], "found")
    self.assertEqual(result["domain"], "protected-only")
    self.assertEqual(result["sync"], "0/3")
    self.assertTrue(result["control_ready"])

  def test_dataflash_scan_finds_protected_only_key_domain(self):
    key = bytes(range(16))
    sync_key = bytes(range(16, 32))
    sync, protected = self._oracle(key, ids=(0x131, 0x2E4), sync_key=sync_key)
    dump = b"\xa5" * 23 + key + b"\x5a" * 29
    result = find_key(dump, sync, protected)
    self.assertEqual(result["status"], "found")
    self.assertEqual(result["offset"], 23)
    self.assertEqual(result["domain"], "protected-only")
    self.assertTrue(result["control_ready"])

  def test_control_key_is_preferred_over_higher_volume_sync_key(self):
    control_key = bytes(range(16))
    sync_key = bytes(range(16, 32))
    sync, protected = self._oracle(control_key, ids=(0x131, 0x2E4),
                                   sync_key=sync_key, sync_count=40)
    sync_offset = 19
    control_offset = 61
    dump = (b"\x99" * sync_offset + sync_key +
            b"\x77" * (control_offset - sync_offset - 16) + control_key + b"\x33" * 20)
    result = find_key(dump, sync, protected)
    self.assertEqual(result["status"], "found")
    self.assertEqual(result["offset"], control_offset)
    self.assertTrue(result["control_ready"])
    alternates = {row["offset"]: row for row in result["alternate_verified"]}
    self.assertIn(sync_offset, alternates)
    self.assertEqual(alternates[sync_offset]["domain"], "sync-only")
    self.assertGreater(alternates[sync_offset]["matches"], result["matches"])

  def test_partial_coverage_scans_only_fully_received_windows(self):
    key = bytes(range(16))
    sync, protected = self._oracle(key, ids=(0x131, 0x2E4))
    dump = b"\xa5" * 23 + key + b"\x5a" * 29
    coverage = bytearray(len(dump))
    coverage[23:39] = b"\x01" * 16
    result = find_key(dump, sync, protected, coverage=bytes(coverage))
    self.assertEqual(result["status"], "found")
    self.assertEqual(result["offset"], 23)
    self.assertTrue(result["coverage_known"])
    self.assertEqual(result["windows_eligible"], 1)

    coverage[38] = 0
    result = find_key(dump, sync, protected, coverage=bytes(coverage))
    self.assertEqual(result["status"], "not_found")
    self.assertEqual(result["windows_eligible"], 0)

  def test_candidate_verification_accepts_firmware_verified_fd_profile(self):
    key = bytes(range(16))
    sync, _ = self._oracle(key, ids=(0x131,))
    trip, reset = sync[-1]["trip"], sync[-1]["reset"]
    subkeys = _cmac_subkeys(key)
    protected = []
    for i in range(32):
      addr = 0x090 if i % 2 == 0 else 0x0D7
      msg_cnt = i & 0xFF
      payload = bytes(((i * 29 + j * 7) & 0xFF) for j in range(28))
      flag = ((msg_cnt & 3) << 2) | (reset & 3)
      msg = addr.to_bytes(2, "big") + payload + _freshness(trip, reset, msg_cnt)
      auth = _first28(_aes_cmac(key, msg, subkeys))
      protected.append({
        "addr": addr, "bus": 1, "payload": payload, "flag": flag,
        "auth": auth, "trip": trip, "reset": reset, "format": "fd32",
      })

    result = verify_candidate_key(key, sync, protected)
    self.assertEqual(result["status"], "found")
    self.assertEqual(result["protected_by_id"], {"0x090": 16, "0x0d7": 16})
    self.assertEqual(result["domain"], "sync+protected")

    dump = b"\x99" * 11 + key + b"\x55" * 20
    scan = find_key(dump, sync, protected)
    self.assertEqual(scan["status"], "found")
    self.assertEqual(scan["offset"], 11)

  def test_candidate_verification_rejects_wrong_key(self):
    key = bytes(range(16))
    sync, protected = self._oracle(key)
    result = verify_candidate_key(bytes(reversed(range(16))), sync, protected)
    self.assertEqual(result["status"], "not_found")
    self.assertLess(result["matches"], 30)


if __name__ == "__main__":
  unittest.main()
