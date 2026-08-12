import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tsk.lib import recovered_key, target_profile


class TestRecoveredKeyAndTargetProfile(unittest.TestCase):
  def test_recovered_key_is_private_and_requires_crypto_verification(self):
    with tempfile.TemporaryDirectory() as directory:
      private = Path(directory) / "private"
      path = private / "recovered-key.json"
      verification = {
        "status": "found",
        "domain": "protected-only",
        "matches": 40,
        "sync": "0/3",
        "protected": "40/40",
        "protected_by_id": {"0x456": 40},
        "protected_by_bus": {"2": 40},
      }
      with patch.multiple(recovered_key, PRIVATE_DIR=private, RECOVERED_KEY_PATH=path):
        public = recovered_key.persist_recovered_key("00112233445566778899aabbccddeeff", verification,
                                                    source="unit-test")
        self.assertTrue(public["recovered"])
        self.assertNotIn("key", public)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(recovered_key.recovered_key_hex(), "00112233445566778899aabbccddeeff")
        with self.assertRaises(ValueError):
          recovered_key.persist_recovered_key("11" * 16, {"status": "not_found"}, source="bad")
        recovered_key.clear_recovered_key()
        self.assertIsNone(recovered_key.load_recovered_key())

  def test_target_profile_never_equates_key_recovery_with_operational_readiness(self):
    with tempfile.TemporaryDirectory() as directory:
      base = Path(directory)
      oracle = base / "oracle.ndjson"
      profile_path = base / "target-profile.json"
      stationary_path = base / "stationary-verification.json"
      integration_path = base / "openpilot-integration.json"
      rows = [
        {"event": "run_start", "run_id": "profile"},
        {"event": "can", "run_id": "profile", "addr": 0x0F, "bus": 1,
         "len": 8, "data": "1234543210000000"},
      ]
      for i, addr in enumerate((0x131, 0x183, 0x2E4)):
        for n in range(3):
          rows.append({
            "event": "can", "run_id": "profile", "addr": addr, "bus": 1, "len": 8,
            "ts_ms": 10 + i * 100 + n * 20,
            "data": bytes((n, i, 2, 3, 0x10, n + 1, n + 2, n + 3)).hex(),
          })
      oracle.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
      identity = {
        "status": "mapped",
        "identity": [
          {"name": "app_sw_id", "ascii": "8965F1208000"},
          {"name": "spare_part_no", "ascii": "89650-TEST"},
        ],
        "eps_tx": "0x7a1", "eps_rx": "0x7a9", "eps_bus": 1, "eps_rx_bus": 1,
        "elm327_param": 1, "semantic_path": "normal-harness", "panda": "unit",
      }
      verification = {
        "status": "found",
        "protected_by_id": {"0x131": 3, "0x183": 3, "0x2e4": 3},
        "protected_by_stream": {"1:0x131": 3, "1:0x183": 3, "1:0x2e4": 3},
      }
      public_key = {
        "recovered": True,
        "key_sha256_prefix": "0123456789abcdef",
        "verification": {},
      }
      with patch.multiple(target_profile,
                          TARGET_PROFILE_PATH=profile_path,
                          STATIONARY_RESULT_PATH=stationary_path,
                          INTEGRATION_MANIFEST_PATH=integration_path), \
           patch("tsk.lib.target_profile.public_recovered_key_status", return_value=public_key):
        profile = target_profile.persist_target_profile(identity, verification=verification,
                                                        oracle_path=oracle)
        self.assertTrue(profile["readiness"]["key_recovered"])
        self.assertTrue(profile["current_openpilot_compatibility"]["lateral_crypto_compatible"])
        self.assertTrue(profile["current_openpilot_compatibility"]["longitudinal_crypto_compatible"])
        self.assertFalse(profile["readiness"]["operational_install_allowed"])
        self.assertTrue(profile["integration"]["missing_fields"])
        original_profile_id = profile["profile_id"]
        original_oracle_hash = profile["oracle"]["sha256"]
        with oracle.open("a", encoding="utf-8") as fh:
          fh.write(json.dumps({"event": "can", "addr": 0x090, "bus": 1, "len": 32,
                               "data": "11" * 32}) + "\n")
        recaptured = target_profile.build_target_profile(identity, verification=verification,
                                                         oracle_path=oracle)
        self.assertEqual(recaptured["profile_id"], original_profile_id)
        self.assertNotEqual(recaptured["oracle"]["sha256"], original_oracle_hash)
        self.assertTrue(any(row["addr_int"] == 0x090 and row["length"] == 32
                            for row in recaptured["can_inventory"]))

        integration_path.write_text(json.dumps({
          "profile_id": profile["profile_id"],
          "reviewed": True,
          "fields": {name: f"known:{name}" for name in target_profile.REQUIRED_INTEGRATION_FIELDS},
          "evidence": {name: f"unit-test source for {name}" for name in target_profile.REQUIRED_INTEGRATION_FIELDS},
        }), encoding="utf-8")
        stationary_path.write_text(json.dumps({
          "profile_id": profile["profile_id"],
          "status": "passed",
          "checks": [{"name": "status_response", "passed": True}],
        }), encoding="utf-8")
        with patch("tsk.lib.opendbc_integration_audit.audit_opendbc_implementation",
                   return_value={"ready": True, "checks": []}):
          ready = target_profile.build_target_profile(identity, verification=verification,
                                                      oracle_path=oracle)
        self.assertTrue(ready["integration"]["ready"])
        self.assertTrue(ready["opendbc_implementation"]["ready"])
        self.assertTrue(ready["stationary_verification"]["passed"])
        self.assertTrue(ready["readiness"]["operational_install_allowed"])


if __name__ == "__main__":
  unittest.main()
