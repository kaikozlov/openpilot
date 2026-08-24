import unittest

from opendbc.can import CANParser
from opendbc.car import Bus, CanData, structs
from opendbc.car.toyota.fingerprints import FINGERPRINTS
from opendbc.car.toyota.interface import CarInterface
from opendbc.car.toyota.values import CAR, DBC, ToyotaFlags


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
    self.assertEqual(eps["EPS_FAULT_INHIBIT"], 0)
    self.assertEqual(eps["DRIVER_TORQUE_INVALID"], 0)

  def test_controller_never_emits_tss3_can(self):
    cp = CarInterface.get_params(CAR.TOYOTA_COROLLA_TSS3, self._fingerprint(1), [], False, False, False)
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
