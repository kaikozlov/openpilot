import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import tsk.lib.ephemeral_runtime as runtime


class TestEphemeralRuntimePackage(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.manifest_raw = runtime.BUILTIN_MANIFEST_PATH.read_bytes()
    cls.audit_raw = runtime.BUILTIN_AUDIT_PATH.read_bytes()
    cls.canary = runtime.BUILTIN_CANARY_PATH.read_bytes()

  def test_builtin_package_is_exact_f181_and_sha_bound(self):
    result = runtime.validate_runtime_package(
      self.manifest_raw, self.audit_raw, self.canary, expected_f181="8965B4512000"
    )
    self.assertTrue(result["canary_static_ready"])
    self.assertTrue(result["raw_substitution_verified"])
    self.assertFalse(result["bridge_artifact_present"])
    self.assertFalse(result["bridge_execution_exposed"])
    self.assertEqual(result["canary_size"], 332)
    self.assertEqual(result["canary_sha256"], "81176c6e1c33451cfa63bd3b4a0e07b8b0fb952c70b3d67442f1a294ed6b651e")
    self.assertEqual(result["target_manifest_sha256"], "e0fddd8204ec9ec34b6cdf88d3b34f24097cef9609d7471f50c181b8ef626395")
    command5 = result["command5_proxy_evidence"]
    self.assertTrue(command5["available"])
    self.assertEqual(command5["dispatcher"], "0x00088350")
    self.assertEqual(command5["driver_record"], 0)
    self.assertEqual(command5["key_selector"], 4)
    self.assertEqual(command5["mailbox"], "0xFEBFFB80")
    self.assertEqual(command5["mailbox_size"], 0x80)
    self.assertEqual(command5["slot4_permission"], "dynamic-unknown")
    self.assertFalse(command5["execution_exposed"])
    self.assertFalse(command5["mailbox_writer_imported"])

  def test_wrong_f181_is_rejected(self):
    with self.assertRaisesRegex(runtime.EphemeralRuntimeError, "does not contain target F181"):
      runtime.validate_runtime_package(
        self.manifest_raw, self.audit_raw, self.canary, expected_f181="8965F4201000"
      )

  def test_foreign_h_f_manifests_are_exact_evidence_only_negative_capability_fixtures(self):
    expected = {
      "8965H1202000": "d2f4d4bd1eff92ae801b5aae3fccfeb94cf0f402f41bf7eb32ae74ef48e9fa38",
      "8965F1208000": "432ccc6801b97e75f96a4fc7cd1e466e87c2064fd368bd298ad17ca8a8c95186",
    }
    for f181, manifest_sha in expected.items():
      path = runtime.FOREIGN_EVIDENCE_MANIFEST_PATHS[f181]
      raw = path.read_bytes()
      self.assertEqual(runtime._sha256(raw), manifest_sha)
      evidence = runtime.inspect_runtime_target_manifest(raw, expected_f181=f181)
      self.assertEqual(evidence["f181"], f181)
      self.assertEqual(evidence["manifest_sha256"], manifest_sha)
      self.assertEqual(evidence["status"], "semantic-resolved-steering-unsupported")
      self.assertFalse(evidence["runtime_build_ready"])
      self.assertTrue(evidence["evidence_only"])
      self.assertEqual(evidence["ram_geometry_status"], "unresolved")
      self.assertFalse(evidence["steering_bridge_applicable"])
      self.assertEqual(evidence["steering_bridge_required_ids"], ["0x2E4", "0x131"])
      self.assertEqual(evidence["steering_bridge_missing_ids"], ["0x2E4", "0x131"])
      self.assertEqual(evidence["secoc_record_count"], 3)
      self.assertFalse(evidence["command5_proxy_evidence"]["available"])
      self.assertFalse(evidence["command5_proxy_evidence"]["execution_exposed"])
      self.assertFalse(evidence["bridge_execution_exposed"])
      self.assertEqual(runtime.builtin_runtime_evidence(f181), evidence)

  def test_foreign_evidence_manifest_never_satisfies_executable_package_gate(self):
    raw = runtime.FOREIGN_EVIDENCE_MANIFEST_PATHS["8965H1202000"].read_bytes()
    with self.assertRaisesRegex(runtime.EphemeralRuntimeError, "not runtime-build-ready"):
      runtime.validate_runtime_package(raw, self.audit_raw, self.canary, expected_f181="8965H1202000")

    # A future regression must not be able to promote this fixture by flipping only
    # the top-level status bits. Its exact image still has no verified retained-RWX
    # geometry, and the executable-package validator must reject on that independent gate.
    doctored = json.loads(raw)
    doctored["status"] = "runtime-build-ready"
    doctored["runtime_build_ready"] = True
    with self.assertRaisesRegex(runtime.EphemeralRuntimeError, "RAM retention geometry is not exact-image verified"):
      runtime.validate_runtime_package(
        json.dumps(doctored).encode(), self.audit_raw, self.canary, expected_f181="8965H1202000"
      )

  def test_foreign_public_status_reports_negative_capability_without_live_readiness(self):
    with patch.object(runtime, "load_runtime_package", return_value=None):
      status = runtime.public_runtime_status("8965F1208000")
    self.assertFalse(status["present"])
    self.assertFalse(status["canary_static_ready"])
    self.assertFalse(status["bridge_execution_exposed"])
    self.assertEqual(status["target_evidence"]["status"], "semantic-resolved-steering-unsupported")
    self.assertEqual(status["target_evidence"]["steering_bridge_missing_ids"], ["0x2E4", "0x131"])
    self.assertIn("evidence-only", status["message"])

  def test_bootstrap_protocol_builder_covers_old_new_and_cpu0_cpu1_without_authorizing_them(self):
    old0 = runtime.bootstrap_protocol_plan(uds_variant="old", cpu_index=0)
    self.assertEqual(old0["did_0203"], b"\x00" * 5)
    self.assertEqual(old0["memory_id"], 1)
    builtin = runtime.builtin_runtime_protocol_plan()
    self.assertEqual(builtin["did_0203"], b"\x00" * 5)  # preserve shipped B4512000 live bytes
    self.assertEqual(builtin["memory_id"], 1)
    self.assertEqual(builtin["routine_magic"], bytes.fromhex("4500"))
    self.assertEqual(old0["request_download"], bytes.fromhex("01460100febf000000001000"))
    self.assertEqual(old0["verify_data"], bytes.fromhex("4500febf000000001000"))
    self.assertEqual(old0["execution_trigger"], bytes.fromhex("3101ff004500000e000000008000"))

    new0 = runtime.bootstrap_protocol_plan(uds_variant="new", cpu_index=0)
    self.assertEqual(new0["did_0203"], bytes.fromhex("0100000000"))
    self.assertEqual(new0["routine_magic"], bytes.fromhex("4501"))
    self.assertEqual(new0["verify_data"][:2], bytes.fromhex("4501"))
    self.assertEqual(new0["execution_trigger"][4:6], bytes.fromhex("4501"))

    old1 = runtime.bootstrap_protocol_plan(uds_variant="old", cpu_index=1)
    self.assertEqual(old1["did_0203"], b"\x00" * 5)
    self.assertEqual(old1["memory_id"], 0)
    self.assertEqual(old1["request_download"], bytes.fromhex("01460000febf000000001000"))

    with self.assertRaisesRegex(runtime.EphemeralRuntimeError, "old or new"):
      runtime.bootstrap_protocol_plan(uds_variant="future", cpu_index=0)
    with self.assertRaisesRegex(runtime.EphemeralRuntimeError, "cpu_index"):
      runtime.bootstrap_protocol_plan(uds_variant="old", cpu_index=2)

  def test_non_build_ready_manifest_is_rejected_before_execution(self):
    manifest = json.loads(self.manifest_raw)
    manifest["runtime_build_ready"] = False
    manifest["status"] = "semantic-resolved-geometry-unresolved"
    with self.assertRaisesRegex(runtime.EphemeralRuntimeError, "not runtime-build-ready"):
      runtime.validate_runtime_package(
        json.dumps(manifest).encode(), self.audit_raw, self.canary, expected_f181="8965B4512000"
      )

  def test_bootstrap_profile_disagreement_is_rejected(self):
    manifest = json.loads(self.manifest_raw)
    manifest["authenticated_bootstrap_profile"]["authenticated_download_base"] = "0xFEBE0000"
    with self.assertRaisesRegex(runtime.EphemeralRuntimeError, "download base disagrees"):
      runtime.validate_runtime_package(
        json.dumps(manifest).encode(), self.audit_raw, self.canary, expected_f181="8965B4512000"
      )

  def test_canary_bytes_must_match_audit(self):
    bad = bytearray(self.canary)
    bad[0] ^= 1
    with self.assertRaisesRegex(runtime.EphemeralRuntimeError, "SHA-256 does not match"):
      runtime.validate_runtime_package(
        self.manifest_raw, self.audit_raw, bytes(bad), expected_f181="8965B4512000"
      )

  def test_audit_must_bind_exact_manifest_bytes(self):
    manifest = json.loads(self.manifest_raw)
    # Semantically harmless formatting/re-serialization still changes the exact imported bytes.
    changed = json.dumps(manifest, separators=(",", ":")).encode()
    self.assertNotEqual(changed, self.manifest_raw)
    with self.assertRaisesRegex(runtime.EphemeralRuntimeError, "exact imported target manifest bytes"):
      runtime.validate_runtime_package(changed, self.audit_raw, self.canary, expected_f181="8965B4512000")

  def test_raw_substitution_plan_writes_callback_last_and_never_exceeds_15_bytes(self):
    plan = runtime._raw_substitution_plan(0xFEBF0000, self.canary, 0xFEBF0FD0)
    self.assertTrue(all(1 <= len(data) <= 15 for _, data in plan[:-1]))
    self.assertEqual(plan[-1], (0xFEBF0FD0, (0xFEBF0000).to_bytes(4, "little")))
    self.assertEqual(b"".join(data for _, data in plan[:-1]), self.canary)

  def test_live_raw_substitution_allowlist_is_exact_codeflash_not_family_wide(self):
    self.assertEqual(runtime.RAW_SUBSTITUTION_VERIFIED_CODEFLASH, {
      "21140bbd65e530a9e518a3e84e20e5d85679675bc09cc724cb177bb7c76bafde"
    })

  def test_boot_seed_delay_is_only_paid_when_nrc37_is_returned(self):
    class RequiredDelay(Exception):
      error_code = 0x37

    class FakeBoot:
      def __init__(self):
        self.calls = 0

      def security_access(self, access_type, *, data_record):
        self.calls += 1
        self.assertions = (access_type, data_record)
        if self.calls == 1:
          raise RequiredDelay
        return b"seed"

    boot = FakeBoot()
    slept = []
    result = runtime._request_boot_seed_with_required_delay(boot, 1, sleep_fn=slept.append)
    self.assertEqual(result, b"seed")
    self.assertEqual(boot.calls, 2)
    self.assertEqual(slept, [runtime.BOOT_SA_REQUIRED_DELAY_SECONDS])
    self.assertEqual(boot.assertions, (1, runtime.SECURITY_ACCESS_DATA_RECORD))

  def test_boot_seed_normal_path_does_not_sleep_and_other_nrc_propagates(self):
    class FakeBoot:
      def security_access(self, access_type, *, data_record):
        return b"seed"

    slept = []
    self.assertEqual(runtime._request_boot_seed_with_required_delay(FakeBoot(), 1, sleep_fn=slept.append), b"seed")
    self.assertEqual(slept, [])

    class WrongFailure(Exception):
      error_code = 0x35

    class FailingBoot:
      def security_access(self, access_type, *, data_record):
        raise WrongFailure

    with self.assertRaises(WrongFailure):
      runtime._request_boot_seed_with_required_delay(FailingBoot(), 1, sleep_fn=slept.append)
    self.assertEqual(slept, [])

  def test_import_persists_only_valid_package_and_optional_fixture_is_hash_bound(self):
    with tempfile.TemporaryDirectory() as td:
      root = Path(td)
      patches = {
        "IMPORTED_MANIFEST_PATH": root / "manifest.json",
        "IMPORTED_AUDIT_PATH": root / "audit.json",
        "IMPORTED_CANARY_PATH": root / "canary.bin",
        "IMPORTED_BOOTSTRAP_PATH": root / "bootstrap.bin",
        "IMPORTED_METADATA_PATH": root / "metadata.json",
        "CANARY_VALIDATION_PATH": root / "validation.json",
      }
      fixture = bytes([0x5A]) * 0x1000
      fixture_sha = runtime._sha256(fixture)
      with patch.multiple(runtime, **patches):
        result = runtime.persist_runtime_package(
          self.manifest_raw, self.audit_raw, self.canary,
          expected_f181="8965B4512000",
          bootstrap_fixture=fixture,
          bootstrap_fixture_sha256=fixture_sha,
          bootstrap_fixture_evidence="isolated target 0x10F0 accepted",
        )
        self.assertTrue(patches["IMPORTED_MANIFEST_PATH"].is_file())
        self.assertEqual(patches["IMPORTED_BOOTSTRAP_PATH"].read_bytes(), fixture)
        self.assertTrue(result["present"])
        self.assertEqual(result["source"], "imported")

  def test_custom_bootstrap_fixture_requires_evidence_note(self):
    with tempfile.TemporaryDirectory() as td:
      root = Path(td)
      fixture = bytes(0x1000)
      with patch.multiple(runtime,
                          IMPORTED_MANIFEST_PATH=root / "manifest.json",
                          IMPORTED_AUDIT_PATH=root / "audit.json",
                          IMPORTED_CANARY_PATH=root / "canary.bin",
                          IMPORTED_BOOTSTRAP_PATH=root / "bootstrap.bin",
                          IMPORTED_METADATA_PATH=root / "metadata.json",
                          CANARY_VALIDATION_PATH=root / "validation.json"):
        with self.assertRaisesRegex(runtime.EphemeralRuntimeError, "evidence note"):
          runtime.persist_runtime_package(
            self.manifest_raw, self.audit_raw, self.canary,
            expected_f181="8965B4512000", bootstrap_fixture=fixture,
            bootstrap_fixture_sha256=runtime._sha256(fixture), bootstrap_fixture_evidence="",
          )

  def test_bench_ack_is_required_before_any_live_path(self):
    with self.assertRaisesRegex(runtime.EphemeralRuntimeError, "isolated-bench acknowledgement"):
      runtime.run_inert_canary(expected_f181="8965B4512000", bench_isolated=False)


if __name__ == "__main__":
  unittest.main()
