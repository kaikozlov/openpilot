import http.client
import json
import re
import threading
import time
import unittest

from tsk.web.server import (
  TSKWebHandler,
  TSKWebServer,
  expected_vehicle_state,
  operation_states_snapshot,
  ready_diff_lock,
  ready_diff_state,
  ready_lock,
  ready_state,
  resolve_asset,
  start_ready_diff_job,
  start_ready_job,
)


class TestServer(unittest.TestCase):
  def test_asset_resolution_rejects_traversal(self):
    self.assertIsNone(resolve_asset("/../launch_chffrplus.sh"))
    self.assertIsNotNone(resolve_asset("/index.html"))

  def test_index_links_resolve(self):
    index = resolve_asset("/index.html").read_text(encoding="utf-8")
    links = set(re.findall(r'href="([^"]+)"', index))
    local_pages = [link for link in links if link.endswith(".html") or link == "/"]
    self.assertTrue(local_pages)
    self.assertTrue(all(resolve_asset(link) is not None for link in local_pages))
    self.assertIn("/api/evidence-bundle", links)

  def test_operation_vehicle_state_annotations(self):
    self.assertIn("READY", expected_vehicle_state("/api/ready-capture"))
    self.assertIn("Not Ready", expected_vehicle_state("/api/uds-sweep"))
    self.assertEqual(expected_vehicle_state("/api/health"), "unspecified")

  def test_operation_snapshot_has_split_ready_states(self):
    snapshot = operation_states_snapshot()
    self.assertIn("ready_passive", snapshot)
    self.assertIn("ready_active_diff", snapshot)
    self.assertEqual(snapshot["ready_passive"]["mode"], "passive")
    self.assertEqual(snapshot["ready_active_diff"]["mode"], "active_diff")

  def test_split_ready_jobs_have_independent_dry_run_results(self):
    self.assertTrue(start_ready_job())
    for _ in range(30):
      with ready_lock:
        status = ready_state["status"]
      if status != "running":
        break
      time.sleep(0.05)
    with ready_lock:
      self.assertEqual(ready_state["status"], "captured")
      self.assertEqual(ready_state["mode"], "passive")
      self.assertEqual(ready_state["diff"], [])

    self.assertTrue(start_ready_diff_job())
    for _ in range(30):
      with ready_diff_lock:
        status = ready_diff_state["status"]
      if status != "running":
        break
      time.sleep(0.05)
    with ready_diff_lock:
      self.assertEqual(ready_diff_state["status"], "complete")
      self.assertEqual(ready_diff_state["mode"], "active_diff")
      self.assertTrue(ready_diff_state["diff"])

  def test_health_endpoint(self):
    server = TSKWebServer(("127.0.0.1", 0), TSKWebHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
      connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
      connection.request("GET", "/api/health")
      response = connection.getresponse()
      body = json.loads(response.read())
      self.assertEqual(response.status, 200)
      self.assertEqual(body["service"], "tsk_web")
      self.assertTrue(body["dry_run"])
    finally:
      server.shutdown()
      server.server_close()
      thread.join(timeout=3)


if __name__ == "__main__":
  unittest.main()
