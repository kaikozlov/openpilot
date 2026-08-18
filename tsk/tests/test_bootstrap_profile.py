import unittest

from tsk.lib.bootstrap_profile import (
  AUTORESET_DATAFLASH_FIXTURE_SHA256,
  BOOTSTRAP_TARGETS,
  BootstrapProfileError,
  DATAFLASH_FIXTURE_SHA256,
  PROFILE_ID,
  RAM_DUMP_FIXTURE_SHA256,
  fixture_is_evidenced,
  known_bootstrap_target,
  public_bootstrap_status,
  require_evidenced_fixture,
)


class TestBootstrapProfile(unittest.TestCase):
  def test_exact_b4_f3_f4_targets_are_evidence_graded(self):
    expected = {
      "8965B4209000", "8965B4233100", "8965B4509100", "8965B4512000",
      "8965B4514000", "8965F3401200", "8965F4207000", "8965F4201000",
    }
    self.assertEqual(set(BOOTSTRAP_TARGETS), expected)
    self.assertEqual(BOOTSTRAP_TARGETS["8965B4512000"].grade, "verified")
    self.assertTrue(all(row.grade == "external-source" for key, row in BOOTSTRAP_TARGETS.items()
                        if key != "8965B4512000"))

  def test_prefix_similarity_never_creates_bootstrap_compatibility(self):
    self.assertIsNone(known_bootstrap_target("8965B4599999"))
    status = public_bootstrap_status("8965B4599999")
    self.assertFalse(status["compatible"])
    self.assertEqual(status["profile_id"], PROFILE_ID)

  def test_public_ram_fixture_is_evidenced_on_legacy_b4_and_4512000(self):
    for f181 in ("8965B4209000", "8965B4233100", "8965B4509100", "8965B4512000"):
      self.assertTrue(fixture_is_evidenced(f181, RAM_DUMP_FIXTURE_SHA256), f181)
      self.assertEqual(require_evidenced_fixture(f181, RAM_DUMP_FIXTURE_SHA256).software_id, f181)

  def test_dataflash_and_autoreset_fixtures_are_locally_pinned_only_on_4512000(self):
    for sha in (DATAFLASH_FIXTURE_SHA256, AUTORESET_DATAFLASH_FIXTURE_SHA256):
      self.assertTrue(fixture_is_evidenced("8965B4512000", sha))
      for f181 in ("8965B4209000", "8965B4233100", "8965B4509100", "8965B4514000",
                   "8965F3401200", "8965F4207000", "8965F4201000"):
        self.assertFalse(fixture_is_evidenced(f181, sha), f181)

  def test_family_compatibility_does_not_imply_fixture_acceptance(self):
    for f181 in ("8965B4514000", "8965F3401200", "8965F4207000", "8965F4201000"):
      status = public_bootstrap_status(f181, fixture_sha256=DATAFLASH_FIXTURE_SHA256)
      self.assertTrue(status["compatible"], f181)
      self.assertFalse(status["fixture_evidenced"], f181)
      with self.assertRaisesRegex(BootstrapProfileError, "not evidenced byte-for-byte"):
        require_evidenced_fixture(f181, DATAFLASH_FIXTURE_SHA256)


if __name__ == "__main__":
  unittest.main()
