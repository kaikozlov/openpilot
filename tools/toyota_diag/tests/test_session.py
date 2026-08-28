import unittest

from opendbc.car.uds import MessageTimeoutError

from tools.toyota_diag import registry, transport
from tools.toyota_diag.session import DiagnosticSession, LifecycleError, LifecycleUnsupported, parse_lifecycle
from tools.toyota_diag.tests import support


def current_p5_lifecycle(keepalive=None, commset=None, **overrides):
  base = {
    "generation": "current-p5",
    "default_session": 1,
    "extended_session": 3,
    "enter_sequence": ["1001", "1003"],
    "return_default": "1001",
  }
  if keepalive is not None:
    base["keepalive"] = keepalive
  if commset is not None:
    base["commset"] = commset
  base.update(overrides)
  return base


class TestLifecycleParsing(unittest.TestCase):
  def test_absent_metadata_is_none_and_v3_still_loads(self):
    profile = registry.load_registry()
    self.assertIsNone(profile.session_control)
    self.assertIsNone(parse_lifecycle(profile))

  def test_enter_sequence_parses_and_legacy_shape_expands_to_sendproc(self):
    profile = support.load_profile(None, session_control=current_p5_lifecycle())
    lifecycle = parse_lifecycle(profile)
    assert lifecycle is not None
    self.assertEqual(lifecycle.enter_sequence, (bytes.fromhex("1001"), bytes.fromhex("1003")))
    self.assertEqual(lifecycle.return_default_request, bytes.fromhex("1001"))

    legacy = support.load_profile(None, session_control=current_p5_lifecycle(
      enter_sequence=None, enter_extended="1003"))
    lifecycle = parse_lifecycle(legacy)
    assert lifecycle is not None
    self.assertEqual(lifecycle.enter_sequence, (bytes.fromhex("1001"), bytes.fromhex("1003")))

  def test_unsupported_generation_and_keepalive_kind_fail_closed(self):
    profile = support.load_profile(None, session_control=current_p5_lifecycle(generation="future-p7"))
    with self.assertRaises(LifecycleUnsupported):
      parse_lifecycle(profile)
    profile = support.load_profile(None, session_control=current_p5_lifecycle(
      keepalive={"kind": "mystery", "interval_s": 1.0}))
    with self.assertRaises(LifecycleUnsupported):
      parse_lifecycle(profile)
    for overrides in (
        {"enter_sequence": ["1003"]},
        {"enter_sequence": ["1001", "1002"]},
        {"enter_sequence": ["1001", "1004"]},
    ):
      profile = support.load_profile(None, session_control=current_p5_lifecycle(**overrides))
      with self.assertRaises(LifecycleUnsupported):
        parse_lifecycle(profile)
    profile = support.load_profile(None, session_control=current_p5_lifecycle(return_default="1003"))
    with self.assertRaises(LifecycleUnsupported):
      parse_lifecycle(profile)

  def test_session_poll_wire_hints_must_match_did(self):
    good = support.load_profile(None, session_control=current_p5_lifecycle(
      keepalive={"kind": "session_did_poll", "interval_s": 2.0, "request": "22F186", "positive_prefix": "62F186"}))
    self.assertEqual(parse_lifecycle(good).keepalive.did, 0xF186)
    bad = support.load_profile(None, session_control=current_p5_lifecycle(
      keepalive={"kind": "session_did_poll", "interval_s": 2.0, "request": "22F187"}))
    with self.assertRaises(registry.RegistryError):
      parse_lifecycle(bad)

  def test_commset_resolution_layering(self):
    profile = support.load_profile(None, session_control=current_p5_lifecycle(
      commset={"uds_timeout_s": 0.5, "response_pending_timeout_s": 3.0}))
    self.assertEqual(registry.commset_timeouts(profile),
                     registry.CommTimeouts(uds_timeout=0.5, response_pending_timeout=3.0))
    row = {"commset": {"uds_timeout_s": 0.8}}
    self.assertEqual(registry.commset_timeouts(profile, row).uds_timeout, 0.8)
    self.assertEqual(registry.commset_timeouts(profile, row).response_pending_timeout, 3.0)
    self.assertEqual(registry.commset_timeouts(registry.load_registry()),
                     registry.CommTimeouts(uds_timeout=0.35, response_pending_timeout=2.0))
    with self.assertRaises(registry.RegistryError):
      registry.commset_timeouts(profile, {"commset": {"uds_timeout_s": 0}})
    with self.assertRaises(registry.RegistryError):
      registry.commset_timeouts(profile, {"commset": {"p2_ms": 10}})


class TestDiagnosticSession(unittest.TestCase):
  def setUp(self):
    self.scripted = support.ScriptedUds()

  def open(self, profile, operation_row=None):
    ecu = support.synthetic_ecu(profile)
    return DiagnosticSession(profile, ecu, client_factory=self.scripted.factory, operation_row=operation_row)

  def test_enter_extended_without_metadata_fails_closed_and_never_transmits(self):
    profile = support.load_profile(None)
    with self.open(profile) as sess:
      with self.assertRaises(LifecycleUnsupported):
        sess.enter_extended(acknowledge=True)
      self.assertEqual(self.scripted.calls, [])

  def test_acknowledgement_is_required_before_any_transition(self):
    profile = support.load_profile(None, session_control=current_p5_lifecycle())
    with self.open(profile) as sess:
      with self.assertRaises(LifecycleError):
        sess.enter_extended()
      self.assertEqual(self.scripted.calls, [])

  def test_sendproc_runs_poll_d1_d2_and_context_exit_restores_default(self):
    lifecycle = current_p5_lifecycle(keepalive={"kind": "session_did_poll", "interval_s": 5.0})
    profile = support.load_profile(None, session_control=lifecycle)
    with self.open(profile) as sess:
      self.scripted.did[support.SYNTH_ECU_ADDRESS] = {0xF186: b"\x01"}  # ECU reports default
      sess.enter_extended(acknowledge=True)
      self.assertEqual([call[1:] for call in self.scripted.calls],
                       [("read_did", 0xF186), ("session", 1), ("session", 3)])
      self.assertTrue(sess.extended)
    self.assertEqual(self.scripted.calls[-1], (support.SYNTH_ECU_ADDRESS, "session", 1))

  def test_poll_reporting_extended_skips_transition_but_cleanup_still_normalizes(self):
    lifecycle = current_p5_lifecycle(keepalive={"kind": "session_did_poll", "interval_s": 5.0})
    profile = support.load_profile(None, session_control=lifecycle)
    with self.open(profile) as sess:
      self.scripted.did[support.SYNTH_ECU_ADDRESS] = {0xF186: b"\x03"}
      sess.enter_extended(acknowledge=True)
      self.assertEqual([call[1:] for call in self.scripted.calls], [("read_did", 0xF186)])
      self.assertEqual(sess.active_session, 3)
    self.assertEqual(self.scripted.calls[-1], (support.SYNTH_ECU_ADDRESS, "session", 1))

  def test_poll_failure_falls_through_to_full_sendproc(self):
    lifecycle = current_p5_lifecycle(keepalive={"kind": "session_did_poll", "interval_s": 5.0})
    profile = support.load_profile(None, session_control=lifecycle)
    with self.open(profile) as sess:
      self.scripted.did[support.SYNTH_ECU_ADDRESS] = {0xF186: MessageTimeoutError()}
      sess.enter_extended(acknowledge=True)
      self.assertEqual([call[1:] for call in self.scripted.calls],
                       [("read_did", 0xF186), ("session", 1), ("session", 3)])

  def test_failed_sendproc_undos_and_reraises(self):
    profile = support.load_profile(None, session_control=current_p5_lifecycle())
    with self.open(profile) as sess:
      self.scripted.session[(support.SYNTH_ECU_ADDRESS, 3)] = MessageTimeoutError()
      with self.assertRaises(MessageTimeoutError):
        sess.enter_extended(acknowledge=True)
      calls = [call[1:] for call in self.scripted.calls]
      self.assertEqual(calls, [("session", 1), ("session", 3), ("session", 1)])
      self.assertFalse(sess.extended)

  def test_exit_cleanup_failure_never_masks_the_in_flight_exception(self):
    profile = support.load_profile(None, session_control=current_p5_lifecycle())
    sess = self.open(profile)
    default_calls = {"count": 0}

    def default_session_script():
      default_calls["count"] += 1
      if default_calls["count"] == 1:
        return None
      raise MessageTimeoutError()

    self.scripted.session[(support.SYNTH_ECU_ADDRESS, 1)] = default_session_script
    with self.assertRaises(RuntimeError):
      with sess:
        sess.enter_extended(acknowledge=True)
        raise RuntimeError("boom")
    self.assertEqual([call[1:] for call in self.scripted.calls], [("session", 1), ("session", 3), ("session", 1)])
    self.assertTrue(sess.cleanup_errors)


  def test_poll_active_session_and_keepalive_kinds(self):
    poll = current_p5_lifecycle(keepalive={"kind": "session_did_poll", "interval_s": 0.01})
    profile = support.load_profile(None, session_control=poll)
    with self.open(profile) as sess:
      self.scripted.did[support.SYNTH_ECU_ADDRESS] = {0xF186: b"\x03"}
      self.assertEqual(sess.poll_active_session(), 3)
      sess.enter_extended(acknowledge=True)  # already extended: no transition TX
      sess.keepalive()
      self.assertEqual(self.scripted.calls[-1], (support.SYNTH_ECU_ADDRESS, "read_did", 0xF186))

    self.setUp()
    tp = current_p5_lifecycle(keepalive={"kind": "tester_present", "interval_s": 0.01})
    profile = support.load_profile(None, session_control=tp)
    with self.open(profile) as sess:
      sess.keepalive()
      self.assertEqual(self.scripted.calls, [(support.SYNTH_ECU_ADDRESS, "tester_present")])

  def test_keepalive_without_metadata_fails_closed(self):
    profile = support.load_profile(None)
    with self.open(profile) as sess:
      with self.assertRaises(LifecycleUnsupported):
        sess.keepalive()

  def test_keepalive_poll_mismatch_is_an_error(self):
    profile = support.load_profile(None, session_control=current_p5_lifecycle(
      keepalive={"kind": "session_did_poll", "interval_s": 5.0}))
    with self.open(profile) as sess:
      sess.enter_extended(acknowledge=True)
      self.scripted.did[support.SYNTH_ECU_ADDRESS] = {0xF186: b"\x01"}  # dropped to default
      with self.assertRaises(LifecycleError):
        sess.keepalive()

  def test_guard_uses_profile_identity_guard(self):
    profile = support.load_profile(None)
    support.guard_pass(self.scripted)
    with self.open(profile) as sess:
      sess.guard(echo=lambda text: None)
    self.assertEqual(self.scripted.calls, [(support.SYNTH_ECU_ADDRESS, "read_did", 0xF181)])
    self.setUp()
    profile = support.load_profile(None)
    self.scripted.did[support.SYNTH_ECU_ADDRESS] = {0xF181: b"OTHER"}
    with self.open(profile) as sess:
      with self.assertRaises(SystemExit):
        sess.guard(echo=lambda text: None)

  def test_operation_row_commset_applies_to_session_timeouts(self):
    profile = support.load_profile(None, session_control=current_p5_lifecycle(
      commset={"uds_timeout_s": 0.5, "response_pending_timeout_s": 3.0}))
    sess = self.open(profile, operation_row={"commset": {"uds_timeout_s": 0.9}})
    self.assertEqual(sess.timeouts, registry.CommTimeouts(uds_timeout=0.9, response_pending_timeout=3.0))

  def test_transport_factory_honors_timeouts(self):
    profile = registry.load_registry()
    panda = support.FakePanda()
    client = transport.uds_client_factory(
      panda, profile, registry.CommTimeouts(uds_timeout=0.9, response_pending_timeout=4.0))(0x7A1)
    self.assertEqual((client.timeout, client.response_pending_timeout), (0.9, 4.0))
    default = transport.uds_client_factory(panda, profile)(0x7A1)
    self.assertEqual((default.timeout, default.response_pending_timeout), (0.35, 2.0))


if __name__ == "__main__":
  unittest.main()
