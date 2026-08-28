import unittest
from types import SimpleNamespace

from opendbc.car import structs
from opendbc.car.can_definitions import CanData
from opendbc.car.structs import car
from opendbc.car.toyota.values import CAR, Ecu
from openpilot.selfdrive.car.toyota_tss3_oracle import (
  FRC_ACC_OPERATION_DID,
  FRC_BUS,
  FRC_LTA_DID,
  FRC_REQUESTS,
  FRC_RX,
  FRC_TX,
  POLL_INTERVAL_NS,
  RESPONSE_STALE_NS,
  ToyotaTSS3FrcOraclePoller,
  configure_toyota_tss3_frc_oracle,
  elm327_diagnostic_ready,
  parse_frc_positive_response,
)


class _Params:
  def __init__(self, enabled: bool, controls_ready: bool = False):
    self.enabled = enabled
    self.controls_ready = controls_ready

  def get_bool(self, key: str) -> bool:
    if key == "ToyotaTSS3FrcOracleCapture":
      return self.enabled
    if key == "ControlsReady":
      return self.controls_ready
    raise AssertionError(key)


def exact_cp(*, passive: bool = True, f181: bytes = b"\x028965F3307000\x00"):
  CP = car.CarParams.new_message()
  CP.carFingerprint = CAR.TOYOTA_CAMRY_TSS3
  CP.passive = passive
  fw = car.CarParams.CarFw.new_message()
  fw.ecu = Ecu.eps
  fw.fwVersion = f181
  CP.carFw = [fw]
  return CP


class TestToyotaTSS3FrcOracle(unittest.TestCase):
  def test_exact_fixed_rdbi_frames_only(self):
    self.assertEqual(FRC_BUS, 1)
    self.assertEqual(FRC_REQUESTS, {
      FRC_LTA_DID: bytes.fromhex("0322160100000000"),
      FRC_ACC_OPERATION_DID: bytes.fromhex("0322191400000000"),
    })
    self.assertEqual(parse_frc_positive_response(bytes.fromhex("0762160101000000")), FRC_LTA_DID)
    self.assertEqual(parse_frc_positive_response(bytes.fromhex("0562191480000000")), FRC_ACC_OPERATION_DID)
    self.assertIsNone(parse_frc_positive_response(bytes.fromhex("037f223100000000")))
    self.assertIsNone(parse_frc_positive_response(bytes.fromhex("0562191580000000")))

  def test_config_is_exact_f33_passive_dev_only(self):
    self.assertIsNotNone(configure_toyota_tss3_frc_oracle(_Params(True), False, exact_cp(), False))
    self.assertIsNone(configure_toyota_tss3_frc_oracle(_Params(False), False, exact_cp(), False))
    self.assertIsNone(configure_toyota_tss3_frc_oracle(_Params(True, controls_ready=True), False, exact_cp(), False))
    self.assertIsNone(configure_toyota_tss3_frc_oracle(_Params(True), True, exact_cp(), False))
    self.assertIsNone(configure_toyota_tss3_frc_oracle(_Params(True), False, exact_cp(passive=False), False))
    self.assertIsNone(configure_toyota_tss3_frc_oracle(_Params(True), False, exact_cp(), True))
    self.assertIsNone(configure_toyota_tss3_frc_oracle(
      _Params(True), False, exact_cp(f181=b"\x028965F3307001\x00"), False,
    ))

    other = exact_cp()
    other.carFingerprint = CAR.TOYOTA_CAMRY
    self.assertIsNone(configure_toyota_tss3_frc_oracle(_Params(True), False, other, False))

  def test_requires_elm327_param1_with_controls_disallowed(self):
    ps = SimpleNamespace(
      safetyModel=structs.CarParams.SafetyModel.elm327, safetyParam=1, controlsAllowed=False,
    )
    self.assertTrue(elm327_diagnostic_ready([ps]))
    ps.safetyParam = 0
    self.assertFalse(elm327_diagnostic_ready([ps]))
    ps.safetyParam = 1
    ps.controlsAllowed = True
    self.assertFalse(elm327_diagnostic_ready([ps]))
    ps.controlsAllowed = False
    ps.safetyModel = structs.CarParams.SafetyModel.noOutput
    self.assertFalse(elm327_diagnostic_ready([ps]))
    self.assertFalse(elm327_diagnostic_ready([]))
    self.assertFalse(elm327_diagnostic_ready([ps, ps]))

  def test_alternates_exact_dids_on_known_frc_bus(self):
    poller = ToyotaTSS3FrcOraclePoller()
    start = 1_000_000_000
    self.assertEqual(poller.poll(start, diagnostics_allowed=True), [
      CanData(FRC_TX, FRC_REQUESTS[FRC_LTA_DID], FRC_BUS),
    ])
    self.assertEqual(poller.poll(start + POLL_INTERVAL_NS - 1, diagnostics_allowed=True), [])
    self.assertEqual(poller.poll(start + POLL_INTERVAL_NS, diagnostics_allowed=True), [
      CanData(FRC_TX, FRC_REQUESTS[FRC_ACC_OPERATION_DID], FRC_BUS),
    ])

  def test_only_exact_bus1_positive_responses_count(self):
    poller = ToyotaTSS3FrcOraclePoller()
    start = 2_000_000_000
    poller.poll(start, diagnostics_allowed=True)
    lta = bytes.fromhex("0762160101000000")
    acc = bytes.fromhex("0562191480000000")
    poller.observe([[CanData(FRC_RX, lta, 0), CanData(FRC_RX, acc, FRC_BUS)]], start + 10_000_000)
    # Bus-0 LTA must not keep the exact bus-1 capture alive.
    self.assertEqual(poller.poll(start + RESPONSE_STALE_NS + 1, diagnostics_allowed=True), [])
    self.assertTrue(poller.stopped)

  def test_both_exact_dids_must_respond_and_remain_fresh(self):
    poller = ToyotaTSS3FrcOraclePoller()
    start = 3_000_000_000
    poller.poll(start, diagnostics_allowed=True)
    lta = bytes.fromhex("0762160101000000")
    acc = bytes.fromhex("0562191480000000")
    poller.observe([[CanData(FRC_RX, lta, FRC_BUS), CanData(FRC_RX, acc, FRC_BUS)]], start + 10_000_000)
    self.assertTrue(poller.poll(start + RESPONSE_STALE_NS, diagnostics_allowed=True))
    self.assertFalse(poller.stopped)

    # Refresh only LTA; stale ACC must still terminate the capture.
    poller.observe([[CanData(FRC_RX, lta, FRC_BUS)]], start + RESPONSE_STALE_NS)
    self.assertEqual(poller.poll(start + 10_000_000 + RESPONSE_STALE_NS + 1, diagnostics_allowed=True), [])
    self.assertTrue(poller.stopped)

  def test_stops_if_exact_oracles_never_respond(self):
    poller = ToyotaTSS3FrcOraclePoller()
    start = 4_000_000_000
    poller.poll(start, diagnostics_allowed=True)
    self.assertEqual(poller.poll(start + RESPONSE_STALE_NS + 1, diagnostics_allowed=True), [])
    self.assertTrue(poller.stopped)

  def test_safety_not_ready_emits_nothing_without_consuming_schedule(self):
    poller = ToyotaTSS3FrcOraclePoller()
    start = 5_000_000_000
    self.assertEqual(poller.poll(start, diagnostics_allowed=False), [])
    self.assertEqual(poller.poll(start + 1, diagnostics_allowed=True), [
      CanData(FRC_TX, FRC_REQUESTS[FRC_LTA_DID], FRC_BUS),
    ])


if __name__ == "__main__":
  unittest.main()
