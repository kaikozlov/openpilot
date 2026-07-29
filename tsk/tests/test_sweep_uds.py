import json
import tempfile
import unittest
from pathlib import Path

from tsk.lib.sweep_uds import (
  RESTORE_REQUESTS,
  Recorder,
  needs_liveness_boundary,
  ordered_services,
  ordered_subfunction_services,
  ordered_subfunctions,
  parse_isotp_frame,
  summarize,
)


class TestSweepScheduling(unittest.TestCase):
  def test_observation_services_precede_stateful_families(self):
    ordered = ordered_services({0x11, 0x22, 0x31, 0x55, 0x3E, 0x85})
    self.assertEqual(ordered[:2], [0x22, 0x3E])
    self.assertLess(ordered.index(0x55), ordered.index(0x11))
    self.assertEqual(ordered[-3:], [0x11, 0x31, 0x85])

  def test_stateful_subfunction_families_run_after_observation_families(self):
    ordered = ordered_subfunction_services({0x10, 0x11, 0x22, 0x31, 0x55})
    self.assertEqual(ordered[:2], [0x22, 0x55])
    self.assertEqual(ordered[-3:], [0x10, 0x11, 0x31])

  def test_programming_subfunction_is_last(self):
    ordered = ordered_subfunctions(0x10)
    self.assertEqual(ordered[:3], [0x01, 0x03, 0x04])
    self.assertEqual(ordered[-1], 0x02)
    self.assertEqual(set(ordered), set(range(256)))

  def test_liveness_boundaries(self):
    self.assertTrue(needs_liveness_boundary(True, 1))
    self.assertTrue(needs_liveness_boundary(False, 16))
    self.assertFalse(needs_liveness_boundary(False, 15))
    self.assertEqual(RESTORE_REQUESTS,
                     (b"\x10\x01", b"\x28\x00\x01", b"\x85\x01", b"\x10\x01"))

  def test_isotp_response_classification(self):
    self.assertEqual(parse_isotp_frame(bytes.fromhex("03500100"))["outcome"], "positive")
    negative = parse_isotp_frame(bytes.fromhex("037f1022"))
    self.assertEqual((negative["outcome"], negative["sid"], negative["nrc"]),
                     ("nrc", 0x10, 0x22))

  def test_recorder_is_append_only_and_resumable(self):
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory) / "sweep.ndjson"
      first = Recorder(str(path))
      first.write("svc:default:22", stage="services/default", label="service 0x22",
                  request="22", outcome="nrc", sid=0x22, nrc=0x13, raw="7f2213", ms=4)
      first.close()
      size_after_first = path.stat().st_size

      second = Recorder(str(path))
      self.assertTrue(second.seen("svc:default:22"))
      second.write("svc:default:23", stage="services/default", label="service 0x23",
                   request="23", outcome="silent", sid=-1, nrc=-1, raw="", ms=50)
      second.close()
      self.assertGreater(path.stat().st_size, size_after_first)

      records = [json.loads(line) for line in path.read_text().splitlines()]
      self.assertEqual(sum(row.get("event") == "run_start" for row in records), 2)
      self.assertEqual(sum(row.get("event") == "run_end" for row in records), 2)
      self.assertTrue(all("run_id" in row and "t_mono_ns" in row for row in records))
      summary = summarize(str(path))
      self.assertIn("service 0x23", summary["silent"])


if __name__ == "__main__":
  unittest.main()
