import copy
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
    self.assertEqual(result["target_manifest_sha256"], "562393d0e40ba8dce158131860e2a2f3f97022cf480ee841247adacfa981b134")

  def test_wrong_f181_is_rejected(self):
    with self.assertRaisesRegex(runtime.EphemeralRuntimeError, "does not contain target F181"):
      runtime.validate_runtime_package(
        self.manifest_raw, self.audit_raw, self.canary, expected_f181="8965F4201000"
      )

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
