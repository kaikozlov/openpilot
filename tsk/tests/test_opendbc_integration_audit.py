import tempfile
import unittest
from pathlib import Path

from tsk.lib.opendbc_integration_audit import audit_opendbc_implementation


class TestOpendbcIntegrationAudit(unittest.TestCase):
  def _fixture(self, root: Path, *, include_f181: bool = True) -> tuple[dict, dict]:
    toyota = root / "opendbc" / "car" / "toyota"
    toyota.mkdir(parents=True)
    generator = root / "opendbc" / "dbc" / "generator" / "toyota"
    generator.mkdir(parents=True)
    (generator / "toyota_secoc_pt.dbc").write_text("VERSION \"unit\"\n", encoding="utf-8")
    (toyota / "values.py").write_text(
      """
from enum import IntFlag
class ToyotaSafetyFlags(IntFlag):
  ALT_BRAKE = (1 << 8)
  STOCK_LONGITUDINAL = (2 << 8)
  LTA = (4 << 8)
  SECOC = (8 << 8)
class ToyotaFlags(IntFlag):
  RADAR_ACC = 64
  ANGLE_CONTROL = 128
  SECOC = 2048
class ToyotaSecOCPlatformConfig(PlatformConfig):
  dbc_dict: dict = field(default_factory=lambda: dbc_dict('toyota_secoc_pt_generated', 'toyota_tss2_adas'))
class CAR(Platforms):
  TOYOTA_CAMRY_TSS3 = ToyotaSecOCPlatformConfig(
    [ToyotaSecOcCarDocs("Toyota Camry test")],
    CarSpecs(mass=1, wheelbase=1, steerRatio=1, tireStiffnessFactor=1),
  )
  TOYOTA_OTHER = PlatformConfig([], CarSpecs(mass=1, wheelbase=1, steerRatio=1, tireStiffnessFactor=1))
EPS_SCALE = defaultdict(lambda: 73,
                        {CAR.TOYOTA_OTHER: 88})
""".lstrip(), encoding="utf-8")
    f181 = "8965F1208000" if include_f181 else "8965F0000000"
    (toyota / "fingerprints.py").write_text(
      f"""
FW_VERSIONS = {{
  CAR.TOYOTA_CAMRY_TSS3: {{
    (Ecu.eps, 0x7a1, None): [b'{f181}'],
  }},
  CAR.TOYOTA_OTHER: {{}},
}}
""".lstrip(), encoding="utf-8")
    (toyota / "interface.py").write_text(
      "EPS_SCALE[candidate]\nToyotaSafetyFlags.SECOC\nToyotaSafetyFlags.LTA\n" +
      "ToyotaSafetyFlags.STOCK_LONGITUDINAL\nret.openpilotLongitudinalControl\n",
      encoding="utf-8")
    (toyota / "carcontroller.py").write_text(
      "create_steer_command\ncreate_lta_steer_command_2\ncreate_accel_command_2\nadd_mac\n",
      encoding="utf-8")
    identity = {"app_sw_id": "8965F1208000"}
    integration = {
      "ready": True,
      "fields": {
        "platform_name": "TOYOTA_CAMRY_TSS3",
        "dbc_pt": "toyota_secoc_pt_generated",
        "safety_flags": "0x849",
        "steer_control_type": "torque",
        "eps_scale": "73",
        "longitudinal_control": "openpilot_default",
        "lateral_command_role": "target evidence",
        "lateral_status_feedback": "target evidence",
        "longitudinal_topology": "camera/default openpilot longitudinal",
      },
    }
    return identity, integration

  def test_exact_target_source_agreement_is_required(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      identity, integration = self._fixture(root)
      result = audit_opendbc_implementation(identity, integration, opendbc_root=root)
      self.assertTrue(result["ready"], result["checks"])
      self.assertEqual(result["source_eps_scale"], 73)
      self.assertEqual(result["source_safety_param"], 0x849)
      self.assertTrue(result["source_sha256"])

  def test_missing_exact_eps_f181_keeps_code_gate_closed(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      identity, integration = self._fixture(root, include_f181=False)
      result = audit_opendbc_implementation(identity, integration, opendbc_root=root)
      self.assertFalse(result["ready"])
      exact = next(check for check in result["checks"] if check["name"] == "exact_eps_f181_present")
      self.assertFalse(exact["passed"])

  def test_longitudinal_and_safety_mismatch_are_detected(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      identity, integration = self._fixture(root)
      integration["fields"]["longitudinal_control"] = "stock_default"
      integration["fields"]["safety_flags"] = "0x849"
      result = audit_opendbc_implementation(identity, integration, opendbc_root=root)
      self.assertFalse(result["ready"])
      failures = {check["name"] for check in result["checks"] if not check["passed"]}
      self.assertIn("longitudinal_control_matches", failures)
      self.assertIn("safety_param_matches", failures)


if __name__ == "__main__":
  unittest.main()
