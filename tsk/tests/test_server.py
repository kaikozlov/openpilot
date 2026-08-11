import http.client
import json
import re
import threading
import time
import unittest
from unittest.mock import patch

from tsk.web.server import (
  TSKWebHandler,
  TSKWebServer,
  dashboard_payload,
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
    self.assertIsNotNone(resolve_asset("/css/app.css"))
    self.assertIsNotNone(resolve_asset("/js/dashboard.js"))
    self.assertIsNotNone(resolve_asset("/js/api.js"))
    self.assertIn('src="/js/dashboard.js"', index)

  def test_dashboard_recovery_state_machine(self):
    base = {
      "identity": {"status": "idle", "identity": [], "eps_bus": -1, "eps_rx_bus": -1,
                   "eps_tx": "", "eps_rx": "", "elm327_param": -1, "semantic_path": ""},
      "can": {"status": "idle", "control_ready": False, "sync_count": 0, "protected_count": 0},
      "dataflash": {"status": "idle", "ready": False, "bytes": 0, "total": 32768},
      "programming": {"status": "idle"},
    }

    def projected(snapshots, installed=False):
      with patch("tsk.web.server.operation_states_snapshot", return_value=snapshots), \
           patch("tsk.web.server.RebootManager.key_status_payload",
                 return_value={"installed": installed, "key": "00" * 16 if installed else None}), \
           patch("tsk.web.server.get_reboot_actions_payload", return_value={}):
        return dashboard_payload()

    self.assertEqual(projected(base)["recovery"]["stage"], "identify")

    mapped = {**base, "identity": {
      "status": "mapped", "identity": [{"name": "app_sw_id", "hex": "31", "ascii": "8965F1208000"}],
      "eps_bus": 1, "eps_rx_bus": 1, "eps_tx": "0x7a1", "eps_rx": "0x7a9",
      "elm327_param": 1, "semantic_path": "normal-harness",
    }}
    self.assertEqual(projected(mapped)["recovery"]["stage"], "capture_can")

    captured = {**mapped, "can": {
      "status": "complete", "control_ready": True, "sync_count": 50, "protected_count": 300,
    }}
    self.assertEqual(projected(captured)["recovery"]["stage"], "programming")

    handoff = {**captured, "programming": {"status": "entered"}}
    self.assertEqual(projected(handoff)["recovery"]["stage"], "dataflash")

    known = {**captured, "identity": {
      **mapped["identity"],
      "identity": [{"name": "app_sw_id", "hex": "31", "ascii": "8965B4509100"}],
    }}
    known_projection = projected(known)
    self.assertTrue(known_projection["vehicle"]["known_transfer"])
    self.assertEqual(known_projection["recovery"]["stage"], "dataflash")

    blocked = {**captured, "programming": {"status": "blocked", "message": "handoff blocked"}}
    blocked_projection = projected(blocked)
    self.assertEqual(blocked_projection["recovery"]["stage"], "programming")
    self.assertEqual(blocked_projection["recovery"]["next_action"]["action"], "research")

    dumped = {**handoff, "dataflash": {
      "status": "complete", "ready": True, "bytes": 32768, "total": 32768,
    }}
    self.assertEqual(projected(dumped)["recovery"]["stage"], "verify")

    complete = projected(base, installed=True)
    self.assertEqual(complete["recovery"]["stage"], "complete")
    self.assertTrue(all(step["state"] == "complete" for step in complete["recovery"]["steps"]))

  def test_probe_pages_share_shell_and_active_pages_require_explicit_run(self):
    probe_pages = (
      "can-collector.html", "can-sniff.html", "dataflash-collector.html", "dataflash-diag.html",
      "extractor.html", "ident-map.html", "level3-probe.html", "preamble-probe.html",
      "prog-probe.html", "read-mem.html", "ready-capture.html", "reset-probe.html",
      "sendkey-probe.html", "uds-sweep.html",
    )
    explicit_run_pages = (
      "can-collector.html", "can-sniff.html", "dataflash-diag.html", "ident-map.html",
      "level3-probe.html", "preamble-probe.html", "prog-probe.html", "read-mem.html",
      "reset-probe.html",
    )

    for page in probe_pages:
      html = resolve_asset(f"/{page}").read_text(encoding="utf-8")
      self.assertIn('href="/css/app.css"', html, page)
      self.assertIn('href="/css/probe.css"', html, page)
      self.assertIn('src="/js/probe.js"', html, page)
      self.assertNotIn("<style>", html, page)
      self.assertIn('id="probeVehicle"', html, page)
      self.assertIn('id="probeRoute"', html, page)

    for page in explicit_run_pages:
      html = resolve_asset(f"/{page}").read_text(encoding="utf-8")
      self.assertIn('id="runBtn"', html, page)
      self.assertIn('runBtn.addEventListener("click"', html, page)

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

  def test_matcher_does_not_install_verified_noncontrol_domain(self):
    result = {
      "status": "found",
      "key": "00112233445566778899aabbccddeeff",
      "address": "0xff201234",
      "matches": 35,
      "sync": "3/3",
      "protected": "32/32",
      "protected_by_id": {"0x116": 16, "0x24d": 16},
      "protected_by_bus": {"1": 32},
      "domain": "sync+protected",
      "control_ready": False,
      "control_matches_by_id": {"0x131": 0, "0x2e4": 0},
      "control_missing": ["0x131", "0x2e4"],
    }
    server = TSKWebServer(("127.0.0.1", 0), TSKWebHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
      with patch("tsk.lib.matcher.run", return_value=result), \
           patch("tsk.web.server.KeyFileManager.install_key") as install, \
           patch("tsk.web.server.RebootManager.key_status_payload", return_value={}), \
           patch("tsk.web.server.record_operation"):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("POST", "/api/match", body=b"{}", headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
      self.assertEqual(response.status, 200)
      self.assertEqual(body["status"], "verified_noncontrol_domain")
      self.assertFalse(body["control_ready"])
      install.assert_not_called()
    finally:
      server.shutdown()
      server.server_close()
      thread.join(timeout=3)

  def test_extract_requires_control_oracle_before_programming(self):
    sync = [{"bus": 1, "trip": i, "reset": i, "auth": 0} for i in range(3)]
    protected = [{"addr": 0x116, "bus": 1} for _ in range(30)]
    server = TSKWebServer(("127.0.0.1", 0), TSKWebHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
      with patch("tsk.lib.matcher.load_oracle_samples", return_value=(sync, protected, 0)), \
           patch("tsk.web.server.TSKExtractor.hack") as hack, \
           patch("tsk.web.server.TSKExtractor._close_panda"), \
           patch("tsk.web.server.record_operation"):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("POST", "/api/extract", body=b"{}", headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
      self.assertEqual(response.status, 409)
      self.assertEqual(body["status"], "oracle_required")
      self.assertEqual(body["control_samples"], {"0x131": 0, "0x2e4": 0})
      hack.assert_not_called()
    finally:
      server.shutdown()
      server.server_close()
      thread.join(timeout=3)

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
