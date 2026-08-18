import struct
import unittest

from tsk.lib.ram_exec_geometry import (
  ANALYZED_8965B4512000_RAM_EXEC,
  COMMITTED_PAYLOAD_CONTRACT,
  COMMUNITY_B4_F3F4_RAM_EXEC,
  LEGACY_8965B4_RAM_EXEC,
  NEWER_TOYOTA_FEBE0000_LINKER_OBSERVATION,
  RamExecGeometry,
  RamExecGeometryError,
  build_request_download_data,
  build_verify_routine_data,
  known_ram_exec_geometry,
  normalize_f181,
  resolve_ram_exec_geometry,
  transfer_chunks,
)


class TestRamExecGeometry(unittest.TestCase):
  def test_exact_known_legacy_f181s_resolve_to_verified_geometry(self):
    for target in (b"\x018965B4209000\x00\x00", b"8965B4233100", "8965B4509100"):
      geometry = resolve_ram_exec_geometry(target)
      self.assertEqual(geometry, LEGACY_8965B4_RAM_EXEC)
      self.assertEqual(geometry.load_addr, 0xFEBF0000)
      self.assertEqual(geometry.size, 0x1000)
      self.assertEqual(geometry.callback_addr, geometry.load_addr)

  def test_cross_vehicle_boot_geometry_covers_evidence_graded_b4_f3_f4_ids(self):
    for target in ("8965B4514000", "8965F3401200", "8965F4207000", "8965F4201000"):
      geometry = resolve_ram_exec_geometry(target)
      self.assertEqual(geometry, COMMUNITY_B4_F3F4_RAM_EXEC)
      self.assertEqual((geometry.load_addr, geometry.size, geometry.callback_addr),
                       (0xFEBF0000, 0x1000, 0xFEBF0000))

  def test_analyzed_4512000_is_separate_from_legacy_ram_key_table_family(self):
    geometry = resolve_ram_exec_geometry(b"\x018965B4512000\x00")
    self.assertEqual(geometry, ANALYZED_8965B4512000_RAM_EXEC)
    self.assertNotIn("8965B4512000", LEGACY_8965B4_RAM_EXEC.target_f181)

  def test_prefix_match_never_promotes_unknown_calibration(self):
    self.assertIsNone(known_ram_exec_geometry("8965B4599999"))
    with self.assertRaisesRegex(RamExecGeometryError, "no authenticated RAM-exec geometry"):
      resolve_ram_exec_geometry("8965B4599999")

  def test_newer_toyota_febe0000_report_is_linker_evidence_not_geometry(self):
    observation = NEWER_TOYOTA_FEBE0000_LINKER_OBSERVATION
    self.assertEqual(observation.link_vma, 0xFEBE0000)
    self.assertIsNone(observation.authenticated_download_addr)
    self.assertIsNone(observation.callback_addr)
    self.assertFalse(observation.public_dict()["usable_for_authenticated_ram_exec"])
    self.assertNotIsInstance(observation, RamExecGeometry)

  def test_explicit_nondefault_geometry_requires_complete_evidence_and_exact_target(self):
    unverified = RamExecGeometry(
      name="candidate",
      load_addr=0xFEBE0000,
      size=0x1000,
      callback_addr=0xFEBE0000,
      target_f181=frozenset({"8965F1208000"}),
      evidence="linker VMA only",
      authenticated_download_verified=False,
      callback_verified=False,
    )
    with self.assertRaisesRegex(RamExecGeometryError, "RequestDownload geometry is not verified"):
      resolve_ram_exec_geometry("8965F1208000", explicit=unverified)

    verified = RamExecGeometry(
      name="future-explicit-verified-example",
      load_addr=0xFEBE0000,
      size=0x800,
      callback_addr=0xFEBE0000,
      target_f181=frozenset({"8965F1208000"}),
      evidence="test fixture: authenticated download, verification, and callback independently verified",
    )
    self.assertEqual(resolve_ram_exec_geometry("8965F1208000", explicit=verified), verified)
    with self.assertRaisesRegex(RamExecGeometryError, "does not cover EPS F181"):
      resolve_ram_exec_geometry("8965F1208001", explicit=verified)

  def test_request_download_and_verify_are_bound_to_same_nondefault_geometry(self):
    geometry = RamExecGeometry(
      name="test-nondefault",
      load_addr=0xFEBE4000,
      size=0x800,
      callback_addr=0xFEBE4000,
      target_f181=frozenset({"TEST00000001"}),
      evidence="deterministic test fixture",
    )
    request = build_request_download_data(geometry)
    verify = build_verify_routine_data(geometry)
    self.assertEqual(request[:4], b"\x01\x46\x01\x00")
    self.assertEqual(struct.unpack("!II", request[4:]), (geometry.load_addr, geometry.size))
    self.assertEqual(verify[:2], b"\x45\x00")
    self.assertEqual(struct.unpack("!II", verify[2:]), (geometry.load_addr, geometry.size))
    chunks = transfer_chunks(bytes(geometry.size), geometry)
    self.assertEqual([len(chunk) for chunk in chunks], [0x400, 0x400])

  def test_committed_payload_rejects_nondefault_callback_or_load_geometry(self):
    wrong_load = RamExecGeometry(
      name="wrong-load",
      load_addr=0xFEBE0000,
      size=0x1000,
      callback_addr=0xFEBE0000,
      target_f181=frozenset({"TEST00000002"}),
      evidence="deterministic test fixture",
    )
    with self.assertRaisesRegex(RamExecGeometryError, "authenticated for load"):
      COMMITTED_PAYLOAD_CONTRACT.validate_geometry(wrong_load)

    wrong_callback = RamExecGeometry(
      name="wrong-callback",
      load_addr=0xFEBF0000,
      size=0x1000,
      callback_addr=0xFEBE0000,
      target_f181=frozenset({"TEST00000003"}),
      evidence="deterministic test fixture",
    )
    with self.assertRaisesRegex(RamExecGeometryError, "callback is"):
      COMMITTED_PAYLOAD_CONTRACT.validate_geometry(wrong_callback)

  def test_transfer_length_must_equal_geometry(self):
    with self.assertRaisesRegex(RamExecGeometryError, "does not match"):
      transfer_chunks(bytes(0x800), LEGACY_8965B4_RAM_EXEC)

  def test_f181_normalization_is_exact_not_prefix_based(self):
    self.assertEqual(normalize_f181(b"\x018965B4509100\x00\x00\x00\x00"), "8965B4509100")
    self.assertEqual(normalize_f181(".8965B4512000...."), "8965B4512000")


if __name__ == "__main__":
  unittest.main()
