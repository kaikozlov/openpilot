import unittest
from unittest.mock import patch

import tsk.lib.diagnostic_route as diagnostic_route
from tsk.lib.diagnostic_route import (
  AmbiguousDiagnosticRouteError, ELM327_NORMAL_PARAM, ELM327_OBD_PARAM,
  discover_eps_route, discover_eps_route_with_routing, matches_uds_response,
  parse_first_isotp, route_fields,
)


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

  def test_physical_routing_prefers_normal_then_obd(self):
    fallback = {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 1,
                "body": "5001", "ms": 2, "source": "prior_address_hypothesis"}
    with patch("tsk.lib.diagnostic_route.configure_elm327") as configure, \
         patch("tsk.lib.diagnostic_route._preferred_eps_candidates", return_value=[]), \
         patch("tsk.lib.diagnostic_route.discover_eps_route", side_effect=[None, fallback]), \
         patch("tsk.lib.diagnostic_route.time.sleep"):
      route = discover_eps_route_with_routing(object(), [0, 1, 2])
    self.assertEqual([call.args[1] for call in configure.call_args_list],
                     [ELM327_NORMAL_PARAM, ELM327_OBD_PARAM, ELM327_OBD_PARAM])
    self.assertEqual(route["elm327_param"], ELM327_OBD_PARAM)
    self.assertEqual(route["semantic_path"], "obd")
    self.assertEqual(route["tx_bus"], 1)

  def test_mirrored_first_response_still_confirms_same_bus_f181(self):
    observed = {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 0, "rx_bus": 2,
                "body": "5001", "ms": 1}
    with patch("tsk.lib.diagnostic_route.probe_response_route", return_value=observed), \
         patch("tsk.lib.diagnostic_route.read_f181", return_value=b"\x018965B4512000") as read_f181:
      routes = diagnostic_route._preferred_eps_candidates(object(), 0x7A1, [0], 0.3)
    self.assertEqual(len(routes), 1)
    self.assertEqual(routes[0]["tx_bus"], 0)
    self.assertEqual(routes[0]["rx_bus"], 0)
    self.assertIn("same_bus_confirmed", routes[0]["source"])
    self.assertEqual(read_f181.call_args.args[1]["rx_bus"], 0)

  def test_duplicate_routes_for_same_eps_choose_first_and_record_alternates(self):
    hits = [
      {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 1, "identity": "383936354131", "body": "5001", "ms": 1},
      {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 0, "rx_bus": 0, "identity": "383936354131", "body": "5001", "ms": 1},
    ]
    with patch("tsk.lib.diagnostic_route.configure_elm327"), \
         patch("tsk.lib.diagnostic_route._preferred_eps_candidates", return_value=hits), \
         patch("tsk.lib.diagnostic_route.time.sleep"):
      route = discover_eps_route_with_routing(object(), [1, 0, 2])
    self.assertEqual(route["tx_bus"], 1)
    self.assertEqual(route["alternate_routes"], [{"tx_bus": 0, "rx_bus": 0, "identity": "383936354131"}])

  def test_multiple_distinct_preferred_eps_responders_fail_closed(self):
    hits = [
      {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 0, "rx_bus": 0, "identity": "383936354131", "body": "5001", "ms": 1},
      {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 1, "identity": "383936354231", "body": "5001", "ms": 1},
    ]
    with patch("tsk.lib.diagnostic_route.configure_elm327"), \
         patch("tsk.lib.diagnostic_route._preferred_eps_candidates", return_value=hits), \
         patch("tsk.lib.diagnostic_route.time.sleep"):
      with self.assertRaises(AmbiguousDiagnosticRouteError):
        discover_eps_route_with_routing(object(), [0, 1, 2])

  def test_rediscovery_confirms_f181_on_preserved_tx_bus(self):
    prior = {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 1,
             "elm327_param": 1, "semantic_path": "normal-harness"}
    raw = {"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 0,
           "body": "5001", "ms": 1, "source": "prior_address_hypothesis"}
    with patch("tsk.lib.diagnostic_route.configure_elm327"), \
         patch("tsk.lib.diagnostic_route.discover_eps_route", return_value=raw), \
         patch("tsk.lib.diagnostic_route.read_f181", return_value=b"\x02" + b"!" * 32) as read_f181:
      found = diagnostic_route.rediscover_route(object(), prior)
    self.assertEqual(found["rx_bus"], 1)
    self.assertEqual(found["source"], "preserved_route_f181_confirmed")
    self.assertEqual(found["elm327_param"], 1)
    self.assertEqual(read_f181.call_args.args[1]["rx_bus"], 1)

  def test_route_fields_include_mux_state(self):
    fields = route_fields({"tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 1,
                           "elm327_param": 1, "semantic_path": "normal-harness"})
    self.assertEqual(fields["eps_bus"], 1)
    self.assertEqual(fields["elm327_param"], 1)
    self.assertEqual(fields["semantic_path"], "normal-harness")


if __name__ == "__main__":
  unittest.main()
