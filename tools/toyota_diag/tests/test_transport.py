from __future__ import annotations

import types
import unittest
from unittest import mock

from opendbc.car.structs import CarParams

from tools.toyota_diag import registry, transport


class _FakePub:
  def __init__(self):
    self.sent = []

  def send(self, payload):
    self.sent.append(payload)


class _FakeSubMaster:
  def __init__(self, states):
    self.states = states
    self.updates = []

  def __getitem__(self, service):
    assert service == "pandaStates"
    return self.states

  def update(self, timeout):
    self.updates.append(timeout)


class _FakeMessaging:
  def __init__(self, states, events=()):
    self.sm = _FakeSubMaster(states)
    self.pub = _FakePub()
    self.can_sock = object()
    self.events = list(events)
    self.drains = []

  def sub_sock(self, service, **kwargs):
    assert service == "can"
    return self.can_sock

  def pub_sock(self, service):
    assert service == "sendcan"
    return self.pub

  def SubMaster(self, services):
    assert services == ["pandaStates"]
    return self.sm

  def drain_sock(self, sock, wait_for_one=False):
    assert sock is self.can_sock
    self.drains.append(wait_for_one)
    events, self.events = self.events, []
    return events


class TestTransport(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.profile = registry.load_registry()

  @staticmethod
  def state(*, safety=CarParams.SafetyModel.elm327, param=1, controls=False):
    return types.SimpleNamespace(safetyModel=safety, safetyParam=param, controlsAllowed=controls)

  def test_managed_ready_is_exact_bus0_elm327_param1_no_controls(self):
    self.assertTrue(transport.managed_diagnostic_ready([self.state()], self.profile))
    self.assertFalse(transport.managed_diagnostic_ready([self.state(param=0)], self.profile))
    self.assertFalse(transport.managed_diagnostic_ready([self.state(controls=True)], self.profile))
    self.assertFalse(transport.managed_diagnostic_ready([self.state(safety=CarParams.SafetyModel.noOutput)], self.profile))
    self.assertFalse(transport.managed_diagnostic_ready([], self.profile))
    self.assertFalse(transport.managed_diagnostic_ready([self.state(), self.state()], self.profile))

  def test_managed_adapter_sends_and_receives_without_changing_safety(self):
    frame = types.SimpleNamespace(address=0x79A, dat=bytes.fromhex("0762160100010000"), src=0)
    event = types.SimpleNamespace(can=[frame])
    messaging = _FakeMessaging([self.state()], [event])
    serialized = []

    def serializer(msgs, msgtype):
      serialized.append((msgs, msgtype))
      return b"serialized-sendcan"

    sleeps = []
    adapter = transport.ManagedPandaAdapter(
      self.profile, messaging_module=messaging, can_serializer=serializer, sleep=sleeps.append,
    )
    adapter.can_send(0x792, bytes.fromhex("0322160100000000"), 0, timeout=350)
    self.assertEqual(serialized, [([(0x792, bytes.fromhex("0322160100000000"), 0)], "sendcan")])
    self.assertEqual(messaging.pub.sent, [b"serialized-sendcan"])
    self.assertEqual(sleeps, [transport.SENDCAN_WARMUP])
    self.assertEqual(adapter.can_recv(), [(0x79A, bytes.fromhex("0762160100010000"), 0)])
    adapter.can_clear(0xFFFF)
    self.assertEqual(messaging.drains, [False, False])

  def test_managed_adapter_rechecks_safety_before_each_tx(self):
    state = self.state()
    messaging = _FakeMessaging([state])
    adapter = transport.ManagedPandaAdapter(
      self.profile, messaging_module=messaging,
      can_serializer=lambda msgs, msgtype: b"unused", sleep=lambda _: None,
    )
    state.controlsAllowed = True
    with self.assertRaisesRegex(SystemExit, "not in diagnostic-safe ELM327/param1"):
      adapter.can_send(0x792, bytes(8), 0)
    self.assertEqual(messaging.pub.sent, [])

  def test_connect_uses_managed_path_when_pandad_owns_panda(self):
    sentinel = object()
    with mock.patch("tools.toyota_diag.transport.pandad_running", return_value=True), \
         mock.patch("tools.toyota_diag.transport.ManagedPandaAdapter", return_value=sentinel) as managed:
      self.assertIs(transport.connect(self.profile), sentinel)
    managed.assert_called_once_with(self.profile)


if __name__ == "__main__":
  unittest.main()
