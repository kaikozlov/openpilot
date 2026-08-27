import unittest

from opendbc.can import CANParser
from opendbc.car import Bus, CanData, structs
from opendbc.car.toyota.fingerprints import FINGERPRINTS
from opendbc.car.toyota.interface import CarInterface
from opendbc.car.toyota.tss3 import decode_eps_394_state_candidates
from opendbc.car.toyota.values import CAR, DBC, TSS3_EXACT_FW_VERSIONS, ToyotaFlags


class TestTSS3ReadOnlyIntegration(unittest.TestCase):
  @staticmethod
  def _fingerprint(bus: int):
    fp = {i: {} for i in range(8)}
    fp[bus] = {0x025: 32, 0x0AA: 8}
    return fp

  def test_checked_out_opendbc_has_passive_corolla_tss3(self):
    cp = CarInterface.get_params(CAR.TOYOTA_COROLLA_TSS3, self._fingerprint(1), [], False, False, False)

    self.assertTrue(cp.flags & ToyotaFlags.TSS3)
    self.assertTrue(cp.flags & ToyotaFlags.SECOC)
    self.assertFalse(cp.flags & ToyotaFlags.TSS2)
    self.assertTrue(cp.flags & ToyotaFlags.TSS3_PT_BUS1)
    self.assertEqual(DBC[CAR.TOYOTA_COROLLA_TSS3][Bus.pt], "toyota_tss3_pt_generated")
    self.assertTrue(cp.dashcamOnly)
    self.assertEqual(cp.safetyConfigs[0].safetyModel, structs.CarParams.SafetyModel.noOutput)
    self.assertTrue(cp.radarUnavailable)
    self.assertFalse(cp.openpilotLongitudinalControl)

  def test_checked_out_opendbc_has_exact_passive_camry_f33(self):
    cp = CarInterface.get_params(CAR.TOYOTA_CAMRY_TSS3, self._fingerprint(1), [], False, False, False)
    self.assertTrue(cp.flags & ToyotaFlags.TSS3)
    self.assertTrue(cp.flags & ToyotaFlags.SECOC)
    self.assertTrue(cp.flags & ToyotaFlags.TSS3_PT_BUS1)
    self.assertEqual(DBC[CAR.TOYOTA_CAMRY_TSS3][Bus.pt], "toyota_tss3_pt_generated")
    self.assertTrue(cp.dashcamOnly)
    self.assertEqual(cp.safetyConfigs[0].safetyModel, structs.CarParams.SafetyModel.noOutput)
    self.assertFalse(cp.openpilotLongitudinalControl)

    exact = TSS3_EXACT_FW_VERSIONS[CAR.TOYOTA_CAMRY_TSS3]
    eps = exact[(structs.CarParams.Ecu.eps, 0x7A1, None)]
    self.assertIn(bytes.fromhex("023839363546333330373030300000000038413331313333303331303000000000"), eps)

  def test_checked_out_camry_394_projection_preserves_ambiguity(self):
    self.assertEqual(decode_eps_394_state_candidates((0, 0, 0, 0)), (0,))
    self.assertEqual(decode_eps_394_state_candidates((0, 3, 0, 0)), (1, 3, 4))
    self.assertEqual(decode_eps_394_state_candidates((0, 7, 0, 0)), (2, 16))

  def test_provisional_span_fingerprint_is_present(self):
    fp = FINGERPRINTS[CAR.TOYOTA_COROLLA_TSS3][0]
    self.assertEqual(len(fp), 147)
    self.assertEqual(fp[0x025], 32)
    self.assertEqual(fp[0x0AA], 8)
    self.assertEqual(fp[0x0D7], 32)

  def test_checked_out_opendbc_decodes_live_tss3_driver_torque(self):
    parser = CANParser("toyota_tss3_pt_generated", [("TSS3_EPS_TELEMETRY", float('nan'))], 1)
    # Span 2026-07-29 moving-rlog frame: B8=11 (1.1 Nm), signed B17 low
    # nibble=-4 (-0.04 Nm), fault/torque-invalid gates both clear.
    dat = bytes.fromhex("0a000000220450b80b002000380006d4020c00000038033b00000000706253c1")
    parser.update([(1_000_000_000, [CanData(0x030, dat, 1)])])
    eps = parser.vl["TSS3_EPS_TELEMETRY"]

    self.assertAlmostEqual(eps["STEERING_WHEEL_TORQUE_COARSE"] + eps["STEERING_WHEEL_TORQUE_FINE"], 1.06, places=6)
    self.assertEqual(eps["STEERING_FAULT_INHIBIT_STATUS"], 0)
    self.assertEqual(eps["DRIVER_TORQUE_INVALID"], 0)

  def test_controller_never_emits_tss3_can(self):
    for candidate in (CAR.TOYOTA_COROLLA_TSS3, CAR.TOYOTA_CAMRY_TSS3):
      with self.subTest(candidate=candidate):
        cp = CarInterface.get_params(candidate, self._fingerprint(1), [], False, False, False)
        ci = CarInterface(cp)
        cc = structs.CarControl()
        cc.enabled = True
        cc.latActive = True
        cc.longActive = True
        cc.actuators.torque = 1.0
        cc.actuators.steeringAngleDeg = 500.0
        cc.actuators.accel = 2.0

        _, can_sends = ci.apply(cc.as_reader(), 1_000_000_000)
        self.assertEqual(can_sends, [])


if __name__ == "__main__":
  unittest.main()
