import json
import tempfile
import unittest
from pathlib import Path

from tsk.lib.capture_ready import analyze_capture, build_mode_diff_worklist


class TestReadyCapture(unittest.TestCase):
  def test_analysis_keeps_unknown_ids_and_annotates_hypotheses(self):
    frames = []
    for i in range(12):
      frames.append((1, 0x555, (b"\x01\x02\x03\x04" + i.to_bytes(4, "big")).hex()))
      frames.append((2, 0x2E4, (b"\x10\x20\x30\x40" + (100 + i).to_bytes(4, "big")).hex()))
      frames.append((1, 0x0F, i.to_bytes(8, "big").hex()))
    result = analyze_capture(frames)
    self.assertEqual(result["ids"], 3)
    self.assertTrue(any(row["addr"] == "0x555" for row in result["candidates"]))
    self.assertTrue(any(row["addr"] == "0x2e4" for row in result["hypothesis_hits"]))
    self.assertTrue(any(row["addr"] == "0x00f" for row in result["sync"]))

  def test_ready_diff_uses_only_characterized_bare_services(self):
    records = [
      {"key": "svc:default:28", "label": "service 0x28", "request": "28",
       "outcome": "silent", "nrc": -1},
      {"key": "svc:extended:22", "label": "service 0x22", "request": "22",
       "outcome": "nrc", "nrc": 0x22},
      {"key": "sub:10:02", "label": "programming", "request": "1002",
       "outcome": "silent", "nrc": -1},
      {"key": "svc:default:11", "label": "service 0x11", "request": "11",
       "outcome": "nrc", "nrc": 0x11},
    ]
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory) / "sweep.ndjson"
      path.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
      worklist = build_mode_diff_worklist(str(path))
    self.assertEqual([(payload.hex(), label) for payload, label in worklist],
                     [("22", "service 0x22"), ("28", "service 0x28")])

  def test_missing_sweep_has_empty_worklist(self):
    self.assertEqual(build_mode_diff_worklist("/definitely/missing/tsk-sweep.ndjson"), [])


if __name__ == "__main__":
  unittest.main()
