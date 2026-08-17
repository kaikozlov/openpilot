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
      "can": {"status": "idle", "ready": False, "sync_count": 0, "protected_count": 0,
              "profile_discovery": {}},
      "dataflash": {"status": "idle", "ready": False, "bytes": 0, "total": 32768},
      "programming": {"status": "idle"},
    }

    def projected(snapshots, *, installed=False, recovered=False, readiness=None):
      readiness = readiness or {}
      recovered_status = {"recovered": recovered, "key_sha256_prefix": "abc123" if recovered else "", "verification": {}}
      profile = {
        "present": recovered,
        "profile_id": "profile-test" if recovered else "",
        "readiness": readiness,
        "unresolved": [] if readiness.get("operational_install_allowed") else ["integration pending"],
      }
      with patch("tsk.web.server.operation_states_snapshot", return_value=snapshots), \
           patch("tsk.web.server.RebootManager.key_status_payload",
                 return_value={"installed": installed, "key": "00" * 16 if installed else None}), \
           patch("tsk.web.server.public_recovered_key_status", return_value=recovered_status), \
           patch("tsk.web.server.public_target_profile_status", return_value=profile), \
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
      "status": "complete", "ready": True, "sync_count": 50, "protected_count": 300,
      "profile_discovery": {"streams": [{"scan_included": True}]},
    }}
    self.assertEqual(projected(captured)["recovery"]["stage"], "programming")

    handoff = {**captured, "programming": {"status": "entered"}}
    handoff_projection = projected(handoff)
    self.assertEqual(handoff_projection["recovery"]["stage"], "ram_geometry")
    self.assertEqual(handoff_projection["recovery"]["next_action"]["action"], "research")
    self.assertFalse(handoff_projection["vehicle"]["ram_exec_geometry"]["ready"])

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

    dumped = {**known, "dataflash": {
      "status": "complete", "ready": True, "bytes": 32768, "total": 32768,
    }}
    self.assertEqual(projected(dumped)["recovery"]["stage"], "verify")

    recovered_projection = projected(dumped, recovered=True)
    self.assertEqual(recovered_projection["recovery"]["stage"], "integration")

    integrated = {"openpilot_integration_reviewed": True, "openpilot_code_ready": False,
                  "stationary_acceptance_verified": False, "operational_install_allowed": False}
    self.assertEqual(projected(dumped, recovered=True, readiness=integrated)["recovery"]["stage"], "implementation")

    implemented = {"openpilot_integration_reviewed": True, "openpilot_code_ready": True,
                   "stationary_acceptance_verified": False, "operational_install_allowed": False}
    self.assertEqual(projected(dumped, recovered=True, readiness=implemented)["recovery"]["stage"], "stationary")

    verified = {"openpilot_integration_reviewed": True, "openpilot_code_ready": True,
                "stationary_acceptance_verified": True, "operational_install_allowed": True}
    self.assertEqual(projected(dumped, recovered=True, readiness=verified)["recovery"]["stage"], "install")
    complete = projected(dumped, installed=True, recovered=True, readiness=verified)
    self.assertEqual(complete["recovery"]["stage"], "complete")
    self.assertTrue(all(step["state"] == "complete" for step in complete["recovery"]["steps"]))

    # A pre-existing key from an older build is not evidence that today's gates passed.
    self.assertNotEqual(projected(dumped, installed=True)["recovery"]["stage"], "complete")

  def test_probe_pages_share_shell_and_active_pages_require_explicit_run(self):
    probe_pages = (
      "can-collector.html", "can-sniff.html", "dataflash-collector.html", "dataflash-diag.html",
      "extractor.html", "ident-map.html", "level3-probe.html", "preamble-probe.html",
      "prog-probe.html", "read-mem.html", "ready-capture.html", "reset-probe.html",
      "sendkey-probe.html", "uds-sweep.html", "xcp-observer.html",
    )
    explicit_run_pages = (
      "can-collector.html", "can-sniff.html", "dataflash-diag.html", "ident-map.html",
      "level3-probe.html", "preamble-probe.html", "prog-probe.html", "read-mem.html",
      "reset-probe.html", "xcp-observer.html",
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

  def test_target_integration_workflow_pages_are_evidence_gated(self):
    target = resolve_asset("/target-profile.html").read_text(encoding="utf-8")
    stationary = resolve_asset("/stationary-verify.html").read_text(encoding="utf-8")
    self.assertIn("/api/target-profile", target)
    self.assertIn("/api/target-profile-manifest", target)
    self.assertIn("Every value requires an evidence source", target)
    self.assertIn("NO KEY INSTALL", target)
    self.assertIn("/api/stationary-plan", stationary)
    self.assertIn("/api/stationary-verify", stationary)
    self.assertIn("zero-actuation", stationary)
    self.assertIn("does not transmit steering commands", stationary)

  def test_dataflash_endpoint_requires_verified_ram_exec_geometry(self):
    server = TSKWebServer(("127.0.0.1", 0), TSKWebHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
      gate = {
        "ready": False, "f181": "8965F1208000", "geometry": None,
        "message": "No authenticated RAM-exec geometry is verified for this exact F181.",
      }
      with patch("tsk.web.server.ram_exec_geometry_status", return_value=gate), \
           patch("tsk.web.server.start_dataflash_job") as start, \
           patch("tsk.web.server.record_operation"):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("POST", "/api/dataflash-dump", body=b"{}", headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
      self.assertEqual(response.status, 409)
      self.assertEqual(body["status"], "ram_exec_geometry_required")
      self.assertIn("No programming", body["message"])
      start.assert_not_called()
    finally:
      server.shutdown()
      server.server_close()
      thread.join(timeout=3)

  def test_operation_vehicle_state_annotations(self):
    self.assertIn("READY", expected_vehicle_state("/api/ready-capture"))
    self.assertIn("Not Ready", expected_vehicle_state("/api/uds-sweep"))
    self.assertIn("Not Ready", expected_vehicle_state("/api/xcp-observer"))
    self.assertEqual(expected_vehicle_state("/api/health"), "unspecified")

  def test_operation_snapshot_has_split_ready_states(self):
    snapshot = operation_states_snapshot()
    self.assertIn("ready_passive", snapshot)
    self.assertIn("ready_active_diff", snapshot)
    self.assertIn("xcp_observer", snapshot)
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

  def test_matcher_recovers_key_without_operational_install(self):
    result = {
      "status": "found",
      "key": "00112233445566778899aabbccddeeff",
      "address": "0xff201234",
      "matches": 35,
      "sync": "3/3",
      "protected": "32/32",
      "protected_by_id": {"0x456": 32},
      "protected_by_bus": {"1": 32},
      "protected_by_stream": {"1:0x456": 32},
      "domain": "protected-only",
      "legacy_lateral_ready": False,
      "legacy_lateral_matches_by_id": {"0x131": 0, "0x2e4": 0},
      "legacy_longitudinal_ready": False,
      "legacy_longitudinal_matches_by_id": {"0x183": 0},
      "alternate_verified": [],
    }
    server = TSKWebServer(("127.0.0.1", 0), TSKWebHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
      with patch("tsk.lib.matcher.run", return_value=result), \
           patch("tsk.web.server.persist_verified_recovery",
                 return_value=({"recovered": True, "key_sha256_prefix": "abc"}, {"profile_id": "p"})) as persist, \
           patch("tsk.web.server.KeyFileManager.install_key") as install, \
           patch("tsk.web.server.RebootManager.key_status_payload", return_value={"installed": False}), \
           patch("tsk.web.server.record_operation"):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("POST", "/api/match", body=b"{}", headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
      self.assertEqual(response.status, 200)
      self.assertEqual(body["status"], "key_recovered")
      self.assertFalse(body["legacy_lateral_ready"])
      persist.assert_called_once()
      install.assert_not_called()
    finally:
      server.shutdown()
      server.server_close()
      thread.join(timeout=3)

  def test_matcher_does_not_auto_install_even_legacy_compatible_key(self):
    result = {
      "status": "found", "key": "00112233445566778899aabbccddeeff",
      "address": "0xff201234", "matches": 40, "sync": "4/4", "protected": "36/36",
      "protected_by_id": {"0x131": 18, "0x2e4": 18}, "protected_by_bus": {"1": 36},
      "protected_by_stream": {"1:0x131": 18, "1:0x2e4": 18}, "domain": "sync+protected",
      "legacy_lateral_ready": True, "legacy_lateral_matches_by_id": {"0x131": 18, "0x2e4": 18},
      "legacy_longitudinal_ready": False, "legacy_longitudinal_matches_by_id": {"0x183": 0},
      "alternate_verified": [],
    }
    server = TSKWebServer(("127.0.0.1", 0), TSKWebHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
      with patch("tsk.lib.matcher.run", return_value=result), \
           patch("tsk.web.server.persist_verified_recovery",
                 return_value=({"recovered": True}, {"profile_id": "p"})), \
           patch("tsk.web.server.KeyFileManager.install_key") as install, \
           patch("tsk.web.server.RebootManager.key_status_payload", return_value={"installed": False}), \
           patch("tsk.web.server.record_operation"):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("POST", "/api/match", body=b"{}", headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
      self.assertEqual(response.status, 200)
      self.assertEqual(body["status"], "key_recovered")
      self.assertTrue(body["legacy_lateral_ready"])
      install.assert_not_called()
    finally:
      server.shutdown()
      server.server_close()
      thread.join(timeout=3)

  def test_extract_uses_generalized_oracle_not_legacy_control_ids(self):
    sync = [{"bus": 1, "trip": i, "reset": i, "auth": 0} for i in range(3)]
    protected = [{"addr": 0x456, "bus": 1} for _ in range(30)]
    verification = {
      "status": "found", "matches": 30, "sync": "0/3", "protected": "30/30",
      "domain": "protected-only", "protected_by_id": {"0x456": 30},
      "legacy_lateral_ready": False,
    }
    server = TSKWebServer(("127.0.0.1", 0), TSKWebHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
      with patch("tsk.lib.matcher.load_oracle_analysis",
                 return_value={"sync_samples": sync, "protected_samples": protected, "streams": []}), \
           patch("tsk.web.server.TSKExtractor.hack", return_value="00112233445566778899aabbccddeeff") as hack, \
           patch("tsk.lib.matcher.verify_candidate_from_oracle", return_value=verification), \
           patch("tsk.web.server.persist_verified_recovery",
                 return_value=({"recovered": True}, {"profile_id": "p"})), \
           patch("tsk.web.server.KeyFileManager.install_key") as install, \
           patch("tsk.web.server.TSKExtractor._close_panda"), \
           patch("tsk.web.server.record_operation"):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("POST", "/api/extract", body=b"{}", headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
      self.assertEqual(response.status, 200)
      self.assertEqual(body["status"], "key_recovered")
      hack.assert_called_once()
      install.assert_not_called()
    finally:
      server.shutdown()
      server.server_close()
      thread.join(timeout=3)

  def test_extract_requires_generalized_crypto_oracle_before_programming(self):
    sync = [{"bus": 1, "trip": i, "reset": i, "auth": 0} for i in range(2)]
    protected = [{"addr": 0x456, "bus": 1} for _ in range(4)]
    server = TSKWebServer(("127.0.0.1", 0), TSKWebHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
      with patch("tsk.lib.matcher.load_oracle_analysis",
                 return_value={"sync_samples": sync, "protected_samples": protected, "streams": []}), \
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
      self.assertNotIn("control_samples", body)
      hack.assert_not_called()
    finally:
      server.shutdown()
      server.server_close()
      thread.join(timeout=3)

  def test_operational_install_endpoint_enforces_profile_gates(self):
    server = TSKWebServer(("127.0.0.1", 0), TSKWebHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
      recovered = {"recovered": True, "key_sha256_prefix": "abc"}
      blocked_profile = {
        "present": True, "recovered_key": {"key_sha256_prefix": "abc"},
        "readiness": {"operational_install_allowed": False}, "unresolved": ["stationary verification"],
      }
      with patch("tsk.web.server.public_recovered_key_status", return_value=recovered), \
           patch("tsk.web.server.public_target_profile_status", return_value=blocked_profile), \
           patch("tsk.web.server.KeyFileManager.install_key") as install, \
           patch("tsk.web.server.record_operation"):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("POST", "/api/install-recovered-key", body=b"{}")
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
      self.assertEqual(response.status, 409)
      self.assertEqual(body["status"], "integration_not_verified")
      install.assert_not_called()

      ready_profile = {**blocked_profile, "readiness": {"operational_install_allowed": True}, "unresolved": []}
      with patch("tsk.web.server.public_recovered_key_status", return_value=recovered), \
           patch("tsk.web.server.public_target_profile_status", return_value=ready_profile), \
           patch("tsk.web.server.recovered_key_hex", return_value="00112233445566778899aabbccddeeff"), \
           patch("tsk.web.server.KeyFileManager.install_key") as install, \
           patch("tsk.web.server.RebootManager.key_status_payload", return_value={"installed": True}), \
           patch("tsk.web.server.record_operation"):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("POST", "/api/install-recovered-key", body=b"{}")
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
      self.assertEqual(response.status, 200)
      self.assertEqual(body["status"], "installed")
      install.assert_called_once_with("00112233445566778899aabbccddeeff")
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
