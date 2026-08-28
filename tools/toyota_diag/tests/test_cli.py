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
  def test_offline_catalog_and_plans_do_not_import_panda(self):
    with mock.patch.dict(sys.modules, {"panda": None}):
      cases = [
        (["ecu", "info", "eps"], "8965F3307000"),
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

  def test_did_read_fails_closed_when_payload_is_short(self):
    scripted = support.ScriptedUds()
    scripted.did[0x7A1] = {0x1037: b"\x00"}
    panda = support.FakePanda()
    with self.patch_live(panda, scripted):
      rc, output = run_cli(["did", "read", "eps", "0x1037"])
    self.assertEqual(rc, 0, output)
    self.assertIn("decode unavailable: bits 0..15 exceed 1-byte DID payload", output)
    self.assertIn("Steering Angle", output)

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
