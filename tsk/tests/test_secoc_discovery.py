import json
import tempfile
import unittest
from pathlib import Path

from tsk.lib.matcher import _aes_cmac, _cmac_subkeys, _first28, _freshness, _sync_input, find_key, load_oracle_analysis


class TestSecocDiscovery(unittest.TestCase):
  @staticmethod
  def _sync_frame(key: bytes, trip: int, reset: int) -> bytes:
    auth = _first28(_aes_cmac(key, _sync_input(trip, reset), _cmac_subkeys(key)))
    reset_bytes = ((reset & 0xFFFFF) << 4).to_bytes(3, "big")
    auth_bytes = auth.to_bytes(4, "big")
    return (trip.to_bytes(2, "big") + reset_bytes[:2] +
            bytes([(reset_bytes[2] & 0xF0) | (auth_bytes[0] & 0x0F)]) + auth_bytes[1:])

  @staticmethod
  def _protected_frame(key: bytes, addr: int, trip: int, reset: int, msg_cnt: int, payload4: bytes) -> bytes:
    to_auth = addr.to_bytes(2, "big") + payload4 + _freshness(trip, reset, msg_cnt)
    auth = _first28(_aes_cmac(key, to_auth, _cmac_subkeys(key)))
    auth_bytes = auth.to_bytes(4, "big")
    flag = ((msg_cnt & 3) << 2) | (reset & 3)
    return payload4 + bytes([(flag << 4) | (auth_bytes[0] & 0x0F)]) + auth_bytes[1:]

  @staticmethod
  def _fd_protected_frame(key: bytes, addr: int, trip: int, reset: int, msg_cnt: int,
                          payload28: bytes, physical_length: int = 32) -> bytes:
    if len(payload28) != 28 or physical_length not in (32, 48, 64):
      raise ValueError
    to_auth = addr.to_bytes(2, "big") + payload28 + _freshness(trip, reset, msg_cnt)
    auth = _first28(_aes_cmac(key, to_auth, _cmac_subkeys(key)))
    auth_bytes = auth.to_bytes(4, "big")
    flag = ((msg_cnt & 3) << 2) | (reset & 3)
    effective = payload28 + bytes([(flag << 4) | (auth_bytes[0] & 0x0F)]) + auth_bytes[1:]
    return effective + bytes([0xA5]) * (physical_length - 32)

  def test_unknown_classic_stream_is_discovered_and_can_find_separate_key(self):
    control_key = bytes(range(16))
    sync_key = bytes(range(16, 32))
    unknown_addr = 0x456
    trip = 0x1234
    reset = 0x54321

    rows = [{"event": "run_start", "run_id": "unknown-profile"}]
    for i in range(40):
      current_trip = (trip + i) & 0xFFFF
      current_reset = (reset + i) & 0xFFFFF
      rows.append({
        "event": "can", "run_id": "unknown-profile", "addr": 0x0F, "bus": 2,
        "len": 8, "ts_ms": i * 5.0, "data": self._sync_frame(sync_key, current_trip, current_reset).hex(),
      })
    trip = (trip + 39) & 0xFFFF
    reset = (reset + 39) & 0xFFFFF
    for i in range(32):
      payload = bytes((i, i ^ 0x55, i ^ 0xAA, (i * 13) & 0xFF))
      rows.append({
        "event": "can", "run_id": "unknown-profile", "addr": unknown_addr, "bus": 2,
        "len": 8, "ts_ms": 210.0 + i * 20.0,
        "data": self._protected_frame(control_key, unknown_addr, trip, reset, i, payload).hex(),
      })
    # An ordinary unrelated stream should not pass the reset-flag structural test.
    for i in range(16):
      rows.append({
        "event": "can", "run_id": "unknown-profile", "addr": 0x555, "bus": 2,
        "len": 8, "ts_ms": 700.0 + i * 20.0,
        "data": (bytes((i, 1, 2, 3, 0x00, i, i ^ 1, i ^ 2))).hex(),
      })

    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory) / "oracle.ndjson"
      path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
      analysis = load_oracle_analysis(path)

    streams = {(row["bus"], row["addr_int"]): row for row in analysis["streams"]}
    candidate = streams[(2, unknown_addr)]
    self.assertFalse(candidate["known_toyota_hypothesis"])
    self.assertTrue(candidate["structural_candidate"])
    self.assertTrue(candidate["scan_included"])
    self.assertEqual(candidate["msg_counter_low2_values"], [0, 1, 2, 3])
    self.assertEqual(candidate["reset_flag_agreement"], 1.0)
    self.assertFalse(streams[(2, 0x555)]["structural_candidate"])
    self.assertFalse(streams[(2, 0x555)]["scan_included"])
    self.assertEqual({sample["addr"] for sample in analysis["protected_samples"]}, {unknown_addr})
    inventory = {(row["bus"], row["addr_int"], row["length"]): row for row in analysis["can_inventory"]}
    self.assertEqual(inventory[(2, unknown_addr, 8)]["samples"], 32)
    self.assertEqual(inventory[(2, 0x555, 8)]["samples"], 16)

    # Put a higher-volume valid sync key earlier in the dump. The target/control
    # protected-domain key must still win candidate selection.
    dump = b"\xA5" * 7 + sync_key + b"\x5A" * 18 + control_key + b"\xC3" * 37
    result = find_key(dump, analysis["sync_samples"], analysis["protected_samples"])
    self.assertEqual(result["status"], "found")
    self.assertEqual(result["offset"], 41)
    self.assertEqual(result["domain"], "protected-only")
    self.assertEqual(result["protected_by_id"], {"0x456": 32})
    self.assertFalse(result["legacy_lateral_ready"])
    self.assertTrue(any(candidate["domain"] == "sync-only" and candidate["matches"] == 40
                        for candidate in result["alternate_verified"]))

  def test_firmware_verified_fd_profile_is_retained_without_classic_reinterpretation(self):
    key = bytes(range(16))
    trip, reset = 0x2200, 0x34560
    rows = [{"event": "run_start", "run_id": "fd"}]
    for i in range(3):
      rows.append({
        "event": "can", "run_id": "fd", "addr": 0x0F, "bus": 1, "len": 8,
        "data": self._sync_frame(key, trip + i, reset + i).hex(),
      })
    trip += 2
    reset += 2
    for i in range(32):
      payload = bytes(((i * 17 + j * 3) & 0xFF) for j in range(28))
      physical_length = 48 if i % 2 else 32
      frame = self._fd_protected_frame(key, 0x090, trip, reset, i, payload, physical_length)
      rows.append({
        "event": "can", "run_id": "fd", "addr": 0x090, "bus": 1,
        "len": physical_length, "data": frame.hex(),
      })
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory) / "oracle.ndjson"
      path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
      analysis = load_oracle_analysis(path)

    stream = next(row for row in analysis["streams"] if row["addr_int"] == 0x090)
    self.assertTrue(stream["known_toyota_hypothesis"])
    self.assertTrue(stream["known_fd_secoc_hypothesis"])
    self.assertFalse(stream["structural_candidate"])
    self.assertTrue(stream["scan_included"])
    self.assertEqual(stream["protected_format"], "fd32")
    self.assertEqual(stream["lengths"], [32, 48])
    self.assertEqual(len(analysis["protected_samples"]), 32)
    self.assertEqual({len(row["payload"]) for row in analysis["protected_samples"]}, {28})
    self.assertEqual({row["physical_length"] for row in analysis["protected_samples"]}, {32, 48})

    inventory = {(row["addr_int"], row["length"]): row for row in analysis["can_inventory"]}
    self.assertEqual(inventory[(0x090, 32)]["samples"], 16)
    self.assertEqual(inventory[(0x090, 48)]["samples"], 16)
    self.assertTrue(inventory[(0x090, 32)]["known_fd_secoc_hypothesis"])

    dump = b"\xA5" * 13 + key + b"\x5A" * 23
    result = find_key(dump, analysis["sync_samples"], analysis["protected_samples"])
    self.assertEqual(result["status"], "found")
    self.assertEqual(result["offset"], 13)
    self.assertEqual(result["protected_by_id"], {"0x090": 32})

  def test_sienna_132_is_now_a_known_classic_profile(self):
    key = bytes(range(16))
    trip, reset = 0x1234, 0x23456
    rows = [
      {"event": "run_start", "run_id": "132"},
      {"event": "can", "run_id": "132", "addr": 0x0F, "bus": 1, "len": 8,
       "data": self._sync_frame(key, trip, reset).hex()},
    ]
    for i in range(8):
      payload = bytes((i, i + 1, i + 2, i + 3))
      rows.append({
        "event": "can", "run_id": "132", "addr": 0x132, "bus": 1, "len": 8,
        "data": self._protected_frame(key, 0x132, trip, reset, i, payload).hex(),
      })
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory) / "oracle.ndjson"
      path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
      analysis = load_oracle_analysis(path)
    row = next(row for row in analysis["streams"] if row["addr_int"] == 0x132)
    self.assertTrue(row["known_classic_secoc_hypothesis"])
    self.assertTrue(row["scan_included"])


if __name__ == "__main__":
  unittest.main()
