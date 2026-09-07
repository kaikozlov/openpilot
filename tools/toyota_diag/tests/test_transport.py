from __future__ import annotations

import types
import unittest
from unittest import mock

from opendbc.car.can_definitions import CanData
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
    cls.profile = registry.load_registry(registry.LEGACY_CAMRY_REGISTRY)

  @staticmethod
  def state(*, safety=CarParams.SafetyModel.elm327, param=1, controls=False):
    return types.SimpleNamespace(safetyModel=safety, safetyParam=param, controlsAllowed=controls)

  def test_managed_ready_requires_elm327_not_a_specific_param_or_controls_state(self):
    self.assertTrue(transport.managed_diagnostic_ready([self.state()], self.profile))
    self.assertTrue(transport.managed_diagnostic_ready([self.state(param=0)], self.profile))
    self.assertTrue(transport.managed_diagnostic_ready([self.state(controls=True)], self.profile))
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

  def test_managed_adapter_rechecks_diagnostic_safety_before_each_tx(self):
    state = self.state()
    messaging = _FakeMessaging([state])
    adapter = transport.ManagedPandaAdapter(
      self.profile, messaging_module=messaging,
      can_serializer=lambda msgs, msgtype: b"unused", sleep=lambda _: None,
    )
    state.safetyModel = CarParams.SafetyModel.toyota
    with self.assertRaisesRegex(SystemExit, "not in ELM327 diagnostic safety"):
      adapter.can_send(0x792, bytes(8), 0)
    self.assertEqual(messaging.pub.sent, [])

  def test_standard_can_query_callbacks_adapt_panda_shape(self):
    from tools.toyota_diag.tests.support import FakePanda
    panda = FakePanda(recv_batches=[[(0x7E8, bytes.fromhex("03490a00"), 0)]])
    can_recv, can_send = transport.can_query_callbacks(panda, wait_timeout=0)
    self.assertEqual(can_recv(wait_for_one=True), [[CanData(0x7E8, bytes.fromhex("03490a00"), 0)]])
    can_send([CanData(0x7DF, bytes.fromhex("0209020000000000"), 0)])
    self.assertEqual(panda.sent, [(0x7DF, bytes.fromhex("0209020000000000"), 0)])

  def test_uds_factory_passes_toyota_subaddress_to_upstream_client(self):
    panda = object()
    sentinel = object()
    with mock.patch("tools.toyota_diag.transport.UdsClient", return_value=sentinel) as uds:
      client = transport.uds_client_factory(panda, self.profile)(0x750, 0x2A)
    self.assertIs(client, sentinel)
    uds.assert_called_once_with(
      panda, 0x750, bus=self.profile.bus, sub_addr=0x2A,
      timeout=self.profile.uds_timeout,
      response_pending_timeout=self.profile.uds_response_pending_timeout,
    )

  def test_connect_uses_managed_path_when_pandad_owns_panda(self):
    sentinel = object()
    with mock.patch("tools.toyota_diag.transport.pandad_running", return_value=True), \
         mock.patch("tools.toyota_diag.transport.ManagedPandaAdapter", return_value=sentinel) as managed:
      self.assertIs(transport.connect(self.profile), sentinel)
    managed.assert_called_once_with(self.profile)

  def test_connect_keeps_normal_harness_routing_unless_obd_multiplexing_is_explicit(self):
    from tools.toyota_diag.tests.support import FakePanda

    for obd_multiplexing, expected_param in ((False, 1), (True, 0)):
      with self.subTest(obd_multiplexing=obd_multiplexing):
        panda = FakePanda()
        with mock.patch("tools.toyota_diag.transport.pandad_running", return_value=False), \
             mock.patch("panda.Panda", return_value=panda):
          self.assertIs(transport.connect(self.profile, obd_multiplexing=obd_multiplexing), panda)
        self.assertEqual(panda.safety, [(CarParams.SafetyModel.elm327, expected_param)])

  def test_status_is_nontransmitting_and_explains_direct_managed_and_blocked(self):
    with mock.patch("tools.toyota_diag.transport.pandad_running", return_value=False):
      direct = transport.status(self.profile)
    self.assertEqual((direct["mode"], direct["ready"]), ("direct-panda", True))
    self.assertIn("normal-harness", direct["detail"])

    with mock.patch("tools.toyota_diag.transport.pandad_running", return_value=False):
      obd = transport.status(self.profile, obd_multiplexing=True)
    self.assertIn("OBD-port", obd["detail"])

    managed_messaging = _FakeMessaging([self.state()])
    with mock.patch("tools.toyota_diag.transport.pandad_running", return_value=True):
      managed = transport.status(self.profile, messaging_module=managed_messaging)
    self.assertEqual((managed["mode"], managed["ready"]), ("managed-sendcan", True))
    self.assertEqual(managed_messaging.pub.sent, [])

    blocked_messaging = _FakeMessaging([self.state(safety=CarParams.SafetyModel.noOutput)])
    with mock.patch("tools.toyota_diag.transport.pandad_running", return_value=True):
      blocked = transport.status(self.profile, messaging_module=blocked_messaging)
    self.assertEqual((blocked["mode"], blocked["ready"]), ("blocked", False))
    self.assertIn("stop openpilot/manager", blocked["detail"])


if __name__ == "__main__":
  unittest.main()
