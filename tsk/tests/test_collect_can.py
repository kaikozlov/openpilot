import json
import tempfile
import unittest
from pathlib import Path

from tsk.lib.collect_can import count_oracle_frames


class TestCollectCan(unittest.TestCase):
  def test_hypothesis_counts_are_bus_agnostic_and_ignore_metadata(self):
    rows = [
      {"event": "run_start", "run_id": "test"},
      {"event": "can", "addr": 0x0F, "bus": 1, "data": "00" * 8},
      {"event": "can", "addr": 0x2E4, "bus": 1, "data": "11" * 8},
      {"event": "can", "addr": 0x555, "bus": 2, "data": "22" * 8},
      {"event": "run_end", "run_id": "test"},
    ]
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory) / "oracle.ndjson"
      path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
      self.assertEqual(count_oracle_frames(path), (1, 1))

  def test_malformed_lines_do_not_break_count(self):
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory) / "oracle.ndjson"
      path.write_text("not-json\n{}\n", encoding="utf-8")
      self.assertEqual(count_oracle_frames(path), (0, 0))


if __name__ == "__main__":
  unittest.main()
