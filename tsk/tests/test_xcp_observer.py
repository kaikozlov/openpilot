#!/usr/bin/env python3
import unittest
from pathlib import Path
from unittest.mock import patch

from tsk.lib.xcp_observer import (
  CONNECT_REQUEST,
  PROFILES,
  XcpObserverError,
  clear_daq_list_request,
  configuration_requests,
  decode_dto,
  probe_xcp,
  set_daq_list_mode_request,
  set_daq_ptr_request,
  short_upload_request,
  start_stop_daq_list_request,
  validate_localram_read,
  write_daq_request,
)


class FakePanda:
  def __init__(self):
    self.pending = []
    self.sent = []
    self.running = False

  def get_version(self):
    return b"fake-panda"

  def can_send(self, addr, data, bus):
    data = bytes(data)
    self.sent.append((addr, data, bus))
    opcode = data[0]
    if opcode == 0xF4:
      length = data[1]
      source = int.from_bytes(data[4:8], "little")
      payload = bytes(((source + i) & 0xFF) for i in range(length))
      response = (b"\xFF" + payload).ljust(8, b"\x00")
    elif opcode == 0xDE and data[1] == 1:
      self.running = True
      response = b"\xFF\x00" + b"\x00" * 6
    elif opcode == 0xDE and data[1] == 0:
      self.running = False
      response = b"\xFF" + b"\x00" * 7
    else:
      response = b"\xFF" + b"\x00" * 7
    self.pending.append((0x7F8, 0, response, bus))

  def can_recv(self):
    if self.pending:
      rows, self.pending = self.pending, []
      return rows
    if self.running:
      return [(0x7F8, 0, bytes.fromhex("0011223344556677"), 1)]
    return []


class TestXcpObserver(unittest.TestCase):
  def test_exact_request_encodings(self):
    self.assertEqual(CONNECT_REQUEST, bytes.fromhex("ff00000000000000"))
    self.assertEqual(short_upload_request(0xFEBE6D28, 7), bytes.fromhex("f4070000286dbefe"))
    self.assertEqual(clear_daq_list_request(), bytes.fromhex("e300000000000000"))
    self.assertEqual(set_daq_ptr_request(2), bytes.fromhex("e200000002000000"))
    self.assertEqual(write_daq_request(0xFEBE6D28), bytes.fromhex("e1ff0100286dbefe"))
    self.assertEqual(set_daq_list_mode_request(), bytes.fromhex("e000000000000100"))
    self.assertEqual(start_stop_daq_list_request(True), bytes.fromhex("de01000000000000"))
    self.assertEqual(start_stop_daq_list_request(False), bytes.fromhex("de00000000000000"))

  def test_profiles_are_within_verified_readable_localram(self):
    for profile in PROFILES.values():
      self.assertLessEqual(len(profile.addresses), 28)
      for address in profile.addresses:
        validate_localram_read(address, 1)
    with self.assertRaises(XcpObserverError):
      validate_localram_read(0xFEBF0300, 1)

  def test_configuration_uses_only_connect_and_daq_subset(self):
    requests = configuration_requests(PROFILES["actuation-discriminator"].addresses)
    self.assertEqual([request[0] for _, request in requests],
                     [0xFF, 0xE3, 0xE2, *([0xE1] * 7), 0xE0, 0xDE])
    self.assertNotIn(0xF0, [request[0] for _, request in requests])
    self.assertNotIn(0xEC, [request[0] for _, request in requests])
    self.assertNotIn(0xE4, [request[0] for _, request in requests])
    self.assertNotIn(0xF5, [request[0] for _, request in requests])
    self.assertNotIn(0xF6, [request[0] for _, request in requests])

  def test_dto_decoder_maps_profile_addresses(self):
    addresses = PROFILES["actuation-discriminator"].addresses
    decoded = decode_dto(bytes.fromhex("0011223344556677"), addresses)
    self.assertEqual(decoded["pid"], 0)
    self.assertEqual(decoded["values"][0], {"address": "0xfebe6d28", "value": 0x11})
    self.assertEqual(decoded["values"][-1], {"address": "0xfebe38a6", "value": 0x77})
    self.assertIsNone(decode_dto(b"\xFF" + b"\x00" * 7, addresses))

  @patch("tsk.lib.xcp_observer.time.sleep", return_value=None)
  @patch("tsk.lib.xcp_observer.subprocess.run")
  @patch("tsk.lib.xcp_observer.configure_elm327")
  @patch("tsk.lib.xcp_observer.discover_eps_route_with_routing")
  @patch("tsk.lib.xcp_observer.TSKExtractor._connect_panda")
  @patch("tsk.lib.xcp_observer.is_agnos", return_value=True)
  def test_unknown_f181_stops_after_connect(self, _agnos, connect, discover, _configure, _run, _sleep):
    panda = FakePanda()
    connect.return_value = panda
    discover.return_value = {
      "tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 1,
      "elm327_param": 1, "semantic_path": "normal-harness",
      "identity": b"8965F1208000".hex(),
    }
    result = probe_xcp()
    self.assertEqual(result["status"], "reachable")
    self.assertEqual([row[1][0] for row in panda.sent], [0xFF])
    self.assertEqual(result["snapshot"], [])
    self.assertEqual(result["frames"], [])

  @patch("tsk.lib.xcp_observer.time.sleep", return_value=None)
  @patch("tsk.lib.xcp_observer.subprocess.run")
  @patch("tsk.lib.xcp_observer.configure_elm327")
  @patch("tsk.lib.xcp_observer.discover_eps_route_with_routing")
  @patch("tsk.lib.xcp_observer.TSKExtractor._connect_panda")
  @patch("tsk.lib.xcp_observer.is_agnos", return_value=True)
  def test_exact_sienna_runs_f4_and_volatile_daq_only(self, _agnos, connect, discover, _configure, _run, _sleep):
    panda = FakePanda()
    connect.return_value = panda
    discover.return_value = {
      "tx": 0x7A1, "rx": 0x7A9, "tx_bus": 1, "rx_bus": 1,
      "elm327_param": 1, "semantic_path": "normal-harness",
      "identity": b"8965B4512000".hex(),
    }
    result = probe_xcp(capture_seconds=0.001, max_frames=3)
    self.assertEqual(result["status"], "observed")
    self.assertEqual(len(result["snapshot"]), 7)
    self.assertGreaterEqual(len(result["frames"]), 1)
    opcodes = [row[1][0] for row in panda.sent]
    self.assertEqual(opcodes[0], 0xFF)
    self.assertEqual(opcodes.count(0xF4), 7)
    self.assertIn(0xE3, opcodes)
    self.assertIn(0xE2, opcodes)
    self.assertIn(0xE1, opcodes)
    self.assertIn(0xE0, opcodes)
    self.assertEqual(opcodes.count(0xDE), 2)  # start + unconditional stop
    self.assertTrue({0xF0, 0xEC, 0xE4, 0xF5, 0xF6}.isdisjoint(opcodes))
    self.assertFalse(result["write_commands_implemented"])

  def test_source_contains_no_generic_xcp_write_or_page_copy_request_builder(self):
    source = Path("tsk/lib/xcp_observer.py").read_text(encoding="utf-8")
    for forbidden in ("bytes((0xF0", "bytes((0xEC", "bytes((0xE4", "bytes((0xF5", "bytes((0xF6"):
      self.assertNotIn(forbidden, source)


if __name__ == "__main__":
  unittest.main()
