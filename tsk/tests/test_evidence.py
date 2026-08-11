import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tsk.lib import evidence


class TestEvidenceBundle(unittest.TestCase):
  def test_bundle_contains_manifest_logs_raw_files_and_payload_hashes(self):
    with tempfile.TemporaryDirectory() as directory:
      base = Path(directory)
      root = base / "cache" / "tsk"
      bundle_dir = root / "evidence"
      payload = base / "payload.bin"
      df_payload = base / "dataflash.bin"
      autoreset_payload = base / "dataflash-autoreset.bin"
      payload.write_bytes(b"payload")
      df_payload.write_bytes(b"dataflash")
      autoreset_payload.write_bytes(b"dataflash-autoreset")
      raw = root / "uds-sweep" / "ready_capture.ndjson"
      raw.parent.mkdir(parents=True)
      raw.write_text('{"event":"can","addr":291}\n', encoding="utf-8")

      with patch.multiple(
          evidence,
          EVIDENCE_ROOT=root,
          BUNDLE_DIR=bundle_dir,
          MANIFEST_PATH=root / "session-manifest.json",
          OPERATION_LOG_PATH=root / "operations.ndjson",
          PAYLOAD_PATH=str(payload),
          DATAFLASH_PAYLOAD_PATH=str(df_payload),
          DATAFLASH_AUTORESET_PAYLOAD_PATH=str(autoreset_payload),
          OPENPILOT_DIR=str(base)):
        evidence.record_operation("/api/ident-map", client="127.0.0.1")
        bundle = evidence.create_evidence_bundle({"identity": {"status": "mapped"}})
        members = evidence.inspect_bundle(bundle)
        manifest = json.loads((root / "session-manifest.json").read_text())

      self.assertIn("tsk-evidence/session-manifest.json", members)
      self.assertIn("tsk-evidence/operations.ndjson", members)
      self.assertIn("tsk-evidence/uds-sweep/ready_capture.ndjson", members)
      self.assertEqual(manifest["schema_version"], 1)
      self.assertEqual(manifest["operation_states"]["identity"]["status"], "mapped")
      self.assertEqual(manifest["payloads"][0]["sha256"], evidence.hashlib.sha256(b"payload").hexdigest())
      self.assertEqual(manifest["payloads"][2]["sha256"],
                       evidence.hashlib.sha256(b"dataflash-autoreset").hexdigest())
      operations = (root / "operations.ndjson").read_text()
      self.assertIn("/api/ident-map", operations)
      self.assertIn("evidence_bundle_requested", operations)


if __name__ == "__main__":
  unittest.main()
