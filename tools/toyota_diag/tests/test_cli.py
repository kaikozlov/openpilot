import sys
import unittest
from contextlib import ExitStack, redirect_stdout
from io import StringIO
from unittest import mock

from tools.toyota_diag import active_test, cli
from tools.toyota_diag.tests import support


def run_cli(argv):
  output = StringIO()
  with redirect_stdout(output):
    rc = cli.main(argv)
  return rc, output.getvalue()


class TestOfflineCli(unittest.TestCase):
  def test_transport_status_is_machine_readable(self):
    state = {"pandad_running": True, "mode": "managed-sendcan", "ready": True, "detail": "ready"}
    with mock.patch("tools.toyota_diag.transport.status", return_value=state):
      rc, output = run_cli(["transport", "status", "--json"])
    self.assertEqual(rc, 0)
    self.assertEqual(__import__("json").loads(output), state)

  def test_search_and_ecu_first_browsing(self):
    rc, output = run_cli(["search", "LTA", "--limit", "20"])
    self.assertEqual(rc, 0, output)
    self.assertIn("did          frc", output)
    self.assertIn("0x1601", output)
    self.assertNotIn("High Voltage Electric Heater", output)

    rc, output = run_cli(["ecu", "frc"])
    self.assertEqual(rc, 0, output)
    self.assertIn("Front Recognition Camera", output)
    self.assertIn("Data List: 148 DID(s), 283 signal(s)", output)

    rc, output = run_cli(["ecu", "frc", "data", "LTA Control"])
    self.assertEqual(rc, 0, output)
    self.assertIn("0x1601", output)
    self.assertIn("LTA Control Condition", output)

  def test_profile_name_alias_resolves_bundled_registry(self):
    rc, output = run_cli(["--profile", "camry-2026-f33", "ecu", "eps"])
    self.assertEqual(rc, 0, output)
    self.assertIn("Power Steering", output)

  def test_vehicle_commands_are_offline_and_machine_readable(self):
    import json
    rc, output = run_cli(["vehicle", "--json"])
    self.assertEqual(rc, 0, output)
    document = json.loads(output)
    self.assertEqual((document["profile"], document["panda_bus"]), ("camry-2026-f33", 0))
    rc, output = run_cli(["vehicle", "list", "--json"])
    self.assertEqual(rc, 0, output)
    rows = json.loads(output)
    self.assertTrue(any(row["profile"] == "camry-2026-f33" for row in rows))

  def test_ecu_typo_suggests_match(self):
    with self.assertRaisesRegex(SystemExit, "did you mean frc"):
      run_cli(["ecu", "frontcam"])

  def test_offline_catalog_and_plans_do_not_import_panda(self):
    with mock.patch.dict(sys.modules, {"panda": None}):
      cases = [
        (["ecu", "info", "eps"], "8965033K9011J2740743"),
        (["ecu", "info", "frc"], "8646C06091"),
        (["can", "topology"], "Power Steering (EPS) via Central Gateway"),
        (["did", "list", "frc", "LTA Control Condition"], "0x1601"),
        (["did", "decode", "eps", "0x1037", "0001"], "Steering Angle: 1.5 deg"),
        (["dtc", "catalog", "frc", "U0131"], "Missing Message"),
        (["active-test", "plan", "frc", "0xA429"], "31011588"),
      ]
      for argv, expected in cases:
        with self.subTest(argv=argv):
          rc, output = run_cli(argv)
          self.assertEqual(rc, 0)
          self.assertIn(expected, output)
    self.assertFalse(hasattr(active_test, "Panda"))
    self.assertFalse(hasattr(active_test, "UdsClient"))


class TestLiveCli(unittest.TestCase):
  def patch_live(self, panda, scripted, raw_response=b"\x62\xF1\x81"):
    stack = ExitStack()
    stack.enter_context(mock.patch("tools.toyota_diag.transport.connect", return_value=panda))
    stack.enter_context(mock.patch("tools.toyota_diag.transport.uds_client_factory", return_value=scripted.factory))
    stack.enter_context(mock.patch("tools.toyota_diag.transport.raw_isotp", return_value=raw_response))
    stack.enter_context(mock.patch("time.sleep", return_value=None))
    return stack

  @staticmethod
  def scripted_clear(post_clear_clean=True):
    scripted = support.ScriptedUds()
    scripted.did[0x7A1] = {0xF181: b"\x00" + support.EXPECTED_EPS_F181 + b"\x00"}
    reads = {"count": 0}
    def engine_dtc():
      reads["count"] += 1
      status = 0 if post_clear_clean and reads["count"] > 1 else 1
      return support.dtc_payload((b"\x00\x01\x21", status))
    scripted.dtc[0x700] = engine_dtc
    return scripted

  @staticmethod
  def mode04_panda():
    return support.FakePanda(recv_batches=[[(addr, b"\x01\x44\x00\x00\x00\x00\x00\x00", 0) for addr in support.LEGISLATED_RESPONDERS]])

  def test_can_sniff_is_receive_only_and_filters_bus_and_address(self):
    import json
    panda = support.FakePanda(recv_batches=[[
      (0x0B6, b"\x01\x02", 0),
      (0x0B6, b"\x99", 1),
      (0x123, b"\x55", 0),
      (0x0B6, b"\x03\x04", 0),
    ]])
    with mock.patch("tools.toyota_diag.transport.passive_receiver", return_value=panda):
      rc, output = run_cli(["can", "sniff", "0xB6", "--duration", "0", "--count", "2", "--json"])
    self.assertEqual(rc, 0, output)
    rows = [json.loads(line) for line in output.splitlines()]
    self.assertEqual([(row["address"], row["bus"], row["data_hex"]) for row in rows], [
      (0x0B6, 0, "0102"), (0x0B6, 0, "0304"),
    ])
    self.assertEqual(panda.sent, [])
    self.assertEqual(panda.safety, [])

  def test_did_read_decodes_gts_engineering_value(self):
    scripted = support.ScriptedUds()
    scripted.did[0x7A1] = {0x1037: bytes.fromhex("0001")}
    panda = support.FakePanda()
    with self.patch_live(panda, scripted):
      rc, output = run_cli(["did", "read", "eps", "0x1037"])
    self.assertEqual(rc, 0, output)
    self.assertEqual(scripted.calls, [(0x7A1, "read_did", 0x1037)])
    self.assertIn("Power Steering DID 0x1037: 0001", output)
    self.assertIn("Steering Angle: 1.5 deg (raw=0x0001)", output)

  def test_did_watch_reuses_client_and_decodes_samples(self):
    scripted = support.ScriptedUds()
    values = iter((bytes.fromhex("0001"), bytes.fromhex("0002")))
    scripted.did[0x7A1] = {0x1037: lambda: next(values)}
    panda = support.FakePanda()
    with self.patch_live(panda, scripted):
      rc, output = run_cli(["did", "watch", "eps", "0x1037", "--interval", "0", "--count", "2"])
    self.assertEqual(rc, 0, output)
    self.assertEqual(scripted.calls, [(0x7A1, "read_did", 0x1037), (0x7A1, "read_did", 0x1037)])
    self.assertIn("[0001] Power Steering DID 0x1037", output)
    self.assertIn("Steering Angle: 1.5 deg", output)
    self.assertIn("[0002] Power Steering DID 0x1037", output)
    self.assertIn("Steering Angle: 3.0 deg", output)

  def test_multi_did_read_reuses_client_and_json_is_machine_readable(self):
    import json
    scripted = support.ScriptedUds()
    scripted.did[0x792] = {
      0x1601: bytes.fromhex("00010000"),
      0x1501: bytes.fromhex("00" * 8),
    }
    panda = support.FakePanda()
    with self.patch_live(panda, scripted):
      rc, output = run_cli(["did", "read", "frc", "0x1601", "0x1501", "--json"])
    self.assertEqual(rc, 0, output)
    self.assertEqual(scripted.calls, [(0x792, "read_did", 0x1601), (0x792, "read_did", 0x1501)])
    document = json.loads(output)
    self.assertEqual([row["did"] for row in document["values"]], [0x1601, 0x1501])
    condition = next(row for row in document["values"][0]["signals"] if row["name"] == "LTA Control Condition")
    self.assertEqual((condition["raw"], condition["pattern"]), (1, "LTA Disabled"))

  def test_watch_json_emits_one_object_per_sample_group(self):
    import json
    scripted = support.ScriptedUds()
    scripted.did[0x792] = {
      0x1601: bytes.fromhex("00010000"),
      0x1501: bytes.fromhex("00" * 8),
    }
    panda = support.FakePanda()
    with self.patch_live(panda, scripted):
      rc, output = run_cli(["did", "watch", "frc", "0x1601", "0x1501", "--interval", "0", "--count", "2", "--json"])
    self.assertEqual(rc, 0, output)
    documents = [json.loads(line) for line in output.splitlines()]
    self.assertEqual([row["sample"] for row in documents], [1, 2])
    self.assertEqual([[value["did"] for value in row["values"]] for row in documents], [[0x1601, 0x1501], [0x1601, 0x1501]])
    self.assertEqual(len(scripted.calls), 4)

  def test_monitor_jsonl_reuses_one_client_and_decodes(self):
    import json
    scripted = support.ScriptedUds()
    scripted.did[0x792] = {0x1601: bytes.fromhex("01000000")}
    panda = support.FakePanda()
    with self.patch_live(panda, scripted):
      rc, output = run_cli(["monitor", "frc", "LTA Control Condition", "--interval", "0", "--count", "2", "--jsonl"])
    self.assertEqual(rc, 0, output)
    documents = [json.loads(line) for line in output.splitlines()]
    self.assertEqual([row["sample"] for row in documents], [1, 2])
    self.assertEqual(scripted.calls, [(0x792, "read_did", 0x1601), (0x792, "read_did", 0x1601)])
    condition = next(signal for signal in documents[0]["values"][0]["signals"] if signal["name"] == "LTA Control Condition")
    self.assertEqual(condition["pattern"], "LTA Enabled")

  def test_scan_builds_high_level_inventory(self):
    import json
    scripted = support.ScriptedUds()
    scripted.dtc[0x7A1] = support.dtc_payload()
    scripted.did[0x7A1] = {
      0xF181: b"\x00" + support.EXPECTED_EPS_F181 + b"\x00",
      0xF18C: b"SERIAL123",
      0x0105: b"PART123",
    }
    panda = support.FakePanda()
    state = {"pandad_running": True, "mode": "managed-sendcan", "ready": True, "detail": "ready"}
    with self.patch_live(panda, scripted), mock.patch("tools.toyota_diag.transport.status", return_value=state):
      rc, output = run_cli(["scan", "--json"])
    self.assertEqual(rc, 0, output)
    document = json.loads(output)
    self.assertEqual((document["profile"], document["responding_ecus"]), ("camry-2026-f33", 1))
    self.assertEqual(document["ecus"][0]["key"], "eps")
    self.assertIn("8965F3307000", document["ecus"][0]["identity"]["0xF181"]["ascii"])

  def test_vehicle_detect_is_read_only_identity_match(self):
    scripted = support.ScriptedUds()
    scripted.did[0x7A1] = {0xF181: support.EXPECTED_EPS_F181}
    panda = support.FakePanda()
    with self.patch_live(panda, scripted):
      rc, output = run_cli(["vehicle", "detect"])
    self.assertEqual(rc, 0, output)
    self.assertIn("camry-2026-f33", output)
    self.assertFalse([call for call in scripted.calls if call[1] != "read_did"])

  def test_did_read_fails_closed_when_payload_is_short(self):
    scripted = support.ScriptedUds()
    scripted.did[0x7A1] = {0x1037: b"\x00"}
    panda = support.FakePanda()
    with self.patch_live(panda, scripted):
      rc, output = run_cli(["did", "read", "eps", "0x1037"])
    self.assertEqual(rc, 0, output)
    self.assertIn("decode unavailable: bits 0..15 exceed 1-byte DID payload", output)
    self.assertIn("Steering Angle", output)

  def test_dtc_scan_json_preserves_status_and_gts_description(self):
    import json
    scripted = support.ScriptedUds()
    scripted.dtc[0x7D2] = support.dtc_payload((bytes.fromhex("C13187"), 0x28))
    panda = support.FakePanda()
    with self.patch_live(panda, scripted):
      rc, output = run_cli(["dtc", "scan", "--json"])
    self.assertEqual(rc, 1, output)
    document = json.loads(output)
    self.assertEqual((document["responding_ecus"], document["fault_status_records"]), (1, 1))
    row = document["ecus"][0]
    self.assertEqual((row["key"], row["address"]), ("hybrid", 0x7D2))
    dtc_row = row["dtcs"][0]
    self.assertEqual((dtc_row["code"], dtc_row["status"], dtc_row["fault_status"]), ("U013187", 0x28, True))
    self.assertIn("CONFIRMED_DTC", dtc_row["status_bits"])
    self.assertEqual(dtc_row["descriptions"][0]["failure"], "Missing Message")

  def test_dtc_clear_preserves_exact_route_and_verifies(self):
    scripted = self.scripted_clear()
    panda = self.mode04_panda()
    with self.patch_live(panda, scripted):
      rc, output = run_cli(["dtc", "clear"])
    self.assertEqual(rc, 0, output)
    self.assertEqual(scripted.calls[0], (0x7A1, "read_did", 0xF181))
    self.assertEqual([call[0] for call in scripted.calls if call[1] == "read_dtc"], [address for _, address in support.CAMRY_ECUS] * 2)
    self.assertEqual([call[:2] for call in scripted.calls if call[1] == "clear"], [(0x700, "clear")])
    self.assertEqual(panda.sent, [(0x7DF, bytes.fromhex("0104000000000000"), 0)])
    self.assertIn("PASS: all responding ECUs are clear", output)

  def test_wrong_identity_blocks_mutation(self):
    scripted = support.ScriptedUds()
    scripted.did[0x7A1] = {0xF181: b"wrong"}
    panda = self.mode04_panda()
    with self.patch_live(panda, scripted):
      with self.assertRaisesRegex(SystemExit, "does not contain"):
        run_cli(["dtc", "clear"])
    self.assertEqual(panda.sent, [])
    self.assertFalse([call for call in scripted.calls if call[1] == "clear"])

  def test_raw_and_functional_mutations_require_force_and_guard(self):
    with mock.patch("tools.toyota_diag.transport.connect", side_effect=AssertionError("must not connect")):
      with self.assertRaisesRegex(SystemExit, "pass --force"):
        run_cli(["uds", "raw", "eps", "0xB0", "0102"])
      with self.assertRaisesRegex(SystemExit, "pass --force"):
        run_cli(["functional", "obd", "0x04"])

    scripted = support.ScriptedUds()
    scripted.did[0x7A1] = {0xF181: support.EXPECTED_EPS_F181}
    panda = support.FakePanda()
    with self.patch_live(panda, scripted, raw_response=b"\xF0\x01"):
      rc, output = run_cli(["uds", "raw", "eps", "0xB0", "0102", "--force"])
    self.assertEqual(rc, 0, output)
    self.assertIn("request:  b00102", output)
    self.assertIn("response: f001", output)
    self.assertEqual(scripted.calls[0], (0x7A1, "read_did", 0xF181))


if __name__ == "__main__":
  unittest.main()
