import unittest

from opendbc.car.uds import DTC_GROUP_TYPE, MessageTimeoutError

from tools.toyota_diag import dtc
from tools.toyota_diag.tests import support


class TestDtc(unittest.TestCase):
  def test_parse_and_scan_fault_mask(self):
    self.assertEqual(dtc.parse_dtc_response(b""), [])
    self.assertEqual(dtc.parse_dtc_response(support.dtc_payload((b"\x00\x01\x21", 0x08))), [("P000121", 0x08)])
    scripted = support.ScriptedUds()
    scripted.dtc[0x700] = support.dtc_payload((b"\x00\x01\x21", 0x01))
    scripted.dtc[0x701] = support.dtc_payload((b"\x00\x02\x22", 0x40))
    responding, faults = dtc.scan(scripted.factory, [(0x700, "Engine"), (0x701, "ECT"), (0x724, "MG")], 0xAF)
    self.assertEqual(sorted(responding), [0x700, 0x701])
    self.assertEqual(faults, [(0x700, "P000121", 0x01)])

  def test_physical_clear_and_exact_functional_mode04(self):
    scripted = support.ScriptedUds()
    scripted.clear[0x700] = None
    scripted.clear[0x701] = support.ScriptedUds.negative_response()
    scripted.clear[0x724] = MessageTimeoutError()
    dtc.clear_physical_uds(scripted.factory, {0x700: "Engine", 0x701: "ECT", 0x724: "MG"}, echo=lambda _: None)
    self.assertEqual([call for call in scripted.calls if call[1] == "clear"], [
      (0x700, "clear", DTC_GROUP_TYPE.ALL), (0x701, "clear", DTC_GROUP_TYPE.ALL), (0x724, "clear", DTC_GROUP_TYPE.ALL),
    ])

    panda = support.FakePanda(recv_batches=[[(addr, b"\x01\x44\x00\x00\x00\x00\x00\x00", 0) for addr in support.LEGISLATED_RESPONDERS]])
    positives = dtc.functional_obd_mode04(panda, frozenset(support.LEGISLATED_RESPONDERS), echo=lambda _: None)
    self.assertEqual(positives, set(support.LEGISLATED_RESPONDERS))
    self.assertEqual(panda.cleared, [0xFFFF])
    self.assertEqual(panda.sent, [(0x7DF, bytes.fromhex("0104000000000000"), 0)])


if __name__ == "__main__":
  unittest.main()
