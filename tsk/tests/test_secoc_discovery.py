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

  def test_unknown_classic_stream_is_discovered_and_can_find_separate_key(self):
    control_key = bytes(range(16))
    sync_key = bytes(range(16, 32))
    unknown_addr = 0x456
    trip = 0x1234
    reset = 0x54321

    rows = [{"event": "run_start", "run_id": "unknown-profile"}]
    rows.append({
      "event": "can", "run_id": "unknown-profile", "addr": 0x0F, "bus": 2,
      "len": 8, "ts_ms": 0.0, "data": self._sync_frame(sync_key, trip, reset).hex(),
    })
    for i in range(32):
      payload = bytes((i, i ^ 0x55, i ^ 0xAA, (i * 13) & 0xFF))
      rows.append({
        "event": "can", "run_id": "unknown-profile", "addr": unknown_addr, "bus": 2,
        "len": 8, "ts_ms": 10.0 + i * 20.0,
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

    dump = b"\xA5" * 41 + control_key + b"\x5A" * 37
    result = find_key(dump, analysis["sync_samples"], analysis["protected_samples"])
    self.assertEqual(result["status"], "found")
    self.assertEqual(result["offset"], 41)
    self.assertEqual(result["domain"], "protected-only")
    self.assertEqual(result["protected_by_id"], {"0x456": 32})
    self.assertFalse(result["legacy_lateral_ready"])

  def test_can_fd_frame_is_never_reinterpreted_as_classic_candidate(self):
    rows = [
      {"event": "run_start", "run_id": "fd"},
      {"event": "can", "addr": 0x0F, "bus": 1, "len": 8, "data": "0001000010000000"},
    ]
    rows.extend(
      {"event": "can", "addr": 0x090, "bus": 1, "len": 32, "data": "11" * 32}
      for _ in range(12)
    )
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory) / "oracle.ndjson"
      path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
      analysis = load_oracle_analysis(path)
    self.assertFalse(any(row["addr_int"] == 0x090 for row in analysis["streams"]))


if __name__ == "__main__":
  unittest.main()
