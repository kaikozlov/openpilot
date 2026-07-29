import unittest
from unittest.mock import patch

from tsk.lib.diagnostic_route import discover_eps_route, matches_uds_response, parse_first_isotp


class TestDiagnosticRoute(unittest.TestCase):
  def test_single_frame_parse(self):
    self.assertEqual(parse_first_isotp(bytes.fromhex("0350 0100".replace(" ", ""))), b"\x50\x01\x00")

  def test_first_frame_parse(self):
    self.assertEqual(parse_first_isotp(bytes.fromhex("100a62f181313233")), bytes.fromhex("62f181313233"))

  def test_non_data_pci_is_ignored(self):
    self.assertIsNone(parse_first_isotp(bytes.fromhex("2101020304050607")))

  def test_fallback_scan_prefers_f181_8965_responder(self):
    def probe(_panda, tx, bus, _payload, _timeout):
      return {"tx": tx, "rx": tx + 8, "tx_bus": bus, "rx_bus": bus,
              "body": "5001", "ms": 1}

    def identity(_panda, route, timeout):
      return b"1234" if route["tx"] == 0x700 else b"8965F1208000"

    with patch("tsk.lib.diagnostic_route.discover_known_route", return_value=None), \
         patch("tsk.lib.diagnostic_route.probe_response_route", side_effect=probe), \
         patch("tsk.lib.diagnostic_route.read_f181", side_effect=identity):
      route = discover_eps_route(object(), [1], addresses=[0x700, 0x701])
    self.assertEqual(route["tx"], 0x701)
    self.assertEqual(route["rx"], 0x709)
    self.assertEqual(route["source"], "address_scan_f181_8965")

  def test_positive_and_negative_response_matching(self):
    self.assertTrue(matches_uds_response(bytes.fromhex("5001"), 0x10))
    self.assertTrue(matches_uds_response(bytes.fromhex("7f1022"), 0x10))
    self.assertFalse(matches_uds_response(bytes.fromhex("7f2722"), 0x10))
    self.assertFalse(matches_uds_response(bytes.fromhex("6201"), 0x10))


if __name__ == "__main__":
  unittest.main()
