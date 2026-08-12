import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tsk.lib import integration_profile, stationary_verification, target_profile


class TestIntegrationGates(unittest.TestCase):
  def _profile(self):
    return {
      "profile_id": "profile-123",
      "readiness": {"key_recovered": True},
      "integration": {"ready": True},
      "opendbc_implementation": {"ready": True},
      "secoc_streams": [
        {"bus": 1, "addr_int": 0x456, "cryptographically_verified": True},
        {"bus": 1, "addr_int": 0x555, "cryptographically_verified": False},
      ],
    }

  def test_reviewed_integration_manifest_requires_every_value_and_evidence_source(self):
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory) / "integration.json"
      profile = self._profile()
      fields = {name: f"value:{name}" for name in target_profile.REQUIRED_INTEGRATION_FIELDS}
      evidence = {name: f"source:{name}" for name in target_profile.REQUIRED_INTEGRATION_FIELDS}
      with patch.object(integration_profile, "INTEGRATION_MANIFEST_PATH", path), \
           patch("tsk.lib.integration_profile.load_target_profile", return_value=profile):
        with self.assertRaisesRegex(ValueError, "missing evidence"):
          incomplete_evidence = dict(evidence)
          incomplete_evidence["eps_scale"] = ""
          integration_profile.save_manifest(profile["profile_id"], fields, incomplete_evidence, reviewed=True)

        saved = integration_profile.save_manifest(profile["profile_id"], fields, evidence, reviewed=True)
        self.assertTrue(saved["reviewed"])
        self.assertEqual(saved["profile_id"], profile["profile_id"])
        template = integration_profile.manifest_template()
        self.assertTrue(template["reviewed"])
        self.assertEqual(len(template["required_fields"]), len(target_profile.REQUIRED_INTEGRATION_FIELDS))

        with self.assertRaisesRegex(ValueError, "does not match"):
          integration_profile.save_manifest("other-profile", fields, evidence, reviewed=True)

  def test_stationary_verification_is_profile_bound_and_requires_zero_actuation_status_and_no_faults(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      capture = root / "stationary" / "session.ndjson"
      capture.parent.mkdir(parents=True)
      capture.write_text('{"event":"stationary-probe-capture"}\n', encoding="utf-8")
      result_path = root / "stationary-verification.json"
      profile = self._profile()
      evidence = {
        "profile_id": profile["profile_id"],
        "stationary": {"max_speed_mps": 0.0, "source": "wheel-speed/status capture"},
        "command": {"stream": "1:0x456", "zero_actuation": True,
                    "cryptographically_verified": True, "frames": 1,
                    "source": "signed command capture"},
        "status": {"acceptance_observed": True, "feedback": "EPS accepted state transition",
                   "source": "EPS status capture"},
        "faults": {"new_faults": [], "source": "before/after DTC snapshot"},
      }
      with patch.object(stationary_verification, "EVIDENCE_ROOT", root), \
           patch.object(stationary_verification, "STATIONARY_RESULT_PATH", result_path), \
           patch("tsk.lib.stationary_verification.load_target_profile", return_value=profile):
        result = stationary_verification.verify_stationary_evidence(
          evidence, capture_path="stationary/session.ndjson"
        )
        self.assertEqual(result["status"], "passed")
        self.assertTrue(all(check["passed"] for check in result["checks"]))
        self.assertEqual(len(result["capture"]["sha256"]), 64)

        bad = json.loads(json.dumps(evidence))
        bad["status"]["acceptance_observed"] = False
        failed = stationary_verification.verify_stationary_evidence(
          bad, capture_path="stationary/session.ndjson"
        )
        self.assertEqual(failed["status"], "failed")
        self.assertFalse(next(check for check in failed["checks"] if check["name"] == "eps_acceptance_feedback")["passed"])

        wrong = json.loads(json.dumps(evidence))
        wrong["profile_id"] = "other"
        with self.assertRaisesRegex(ValueError, "not bound"):
          stationary_verification.verify_stationary_evidence(wrong, capture_path="stationary/session.ndjson")

        outside = root.parent / "outside.txt"
        outside.write_text("x")
        with self.assertRaisesRegex(ValueError, "under /cache/tsk"):
          stationary_verification.verify_stationary_evidence(evidence, capture_path="../outside.txt")


if __name__ == "__main__":
  unittest.main()
