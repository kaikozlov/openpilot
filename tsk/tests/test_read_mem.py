#!/usr/bin/env python3
import unittest
from types import SimpleNamespace

from tsk.lib.read_mem import (
  ACTUATION_OBSERVATION,
  APPLICATION_SA_MIRRORS,
  APPLICATION_SA_ROOT_EXPECTED,
  BOOT_PAYLOAD_KEY_RESIDUE,
  DATAFLASH_ID,
  KEY_ADDR,
  RAM_ID,
  application_sa_mirror_for_f181,
  application_sa_recovery_plan,
  memory_id_request_data,
  read_memory_with_id,
  sienna_policy,
)


class FakeUds:
  def __init__(self, payload: bytes):
    self.payload = payload
    self.calls = []

  def _uds_request(self, service, *, subfunction=None, data=None):
    self.calls.append((service, subfunction, data))
    return self.payload


class TestReadMemoryProbe(unittest.TestCase):
  def test_exact_sienna_memory_id_request_shapes(self):
    self.assertEqual(
      memory_id_request_data(DATAFLASH_ID, 0xFF200000, 0x10),
      bytes.fromhex("1502ff20000010"),
    )
    self.assertEqual(
      memory_id_request_data(RAM_ID, BOOT_PAYLOAD_KEY_RESIDUE, 0x10),
      bytes.fromhex("1501febf2d0810"),
    )
    self.assertEqual(
      memory_id_request_data(RAM_ID, ACTUATION_OBSERVATION, 0x04),
      bytes.fromhex("1501febe6d2804"),
    )

  def test_memory_id_request_rejects_invalid_ranges(self):
    with self.assertRaises(ValueError):
      memory_id_request_data(0, 0xFEBF2D08, 16)
    with self.assertRaises(ValueError):
      memory_id_request_data(RAM_ID, 0xFEBF2D08, 0)
    with self.assertRaises(ValueError):
      memory_id_request_data(RAM_ID, 0xFFFFFFFE, 4)

  def test_sienna_policy_matches_recovered_exclusions(self):
    self.assertEqual(sienna_policy(DATAFLASH_ID, 0xFF200000, 16), "firmware-readable")
    self.assertEqual(sienna_policy(DATAFLASH_ID, KEY_ADDR, 16), "firmware-excluded")
    self.assertEqual(sienna_policy(RAM_ID, BOOT_PAYLOAD_KEY_RESIDUE, 16), "firmware-readable")
    self.assertEqual(sienna_policy(RAM_ID, ACTUATION_OBSERVATION, 4), "firmware-readable")
    self.assertEqual(sienna_policy(RAM_ID, 0xFEBE37FC, 8), "firmware-excluded")

  def test_application_sa_recovery_is_exact_f181_gated(self):
    self.assertEqual(application_sa_mirror_for_f181("8965B4512000"), 0xFEBF7BE0)
    self.assertEqual(application_sa_mirror_for_f181(b"\x018965H1202000\x00"), 0xFEBF7B80)
    self.assertEqual(application_sa_mirror_for_f181("8965F1208000"), 0xFEBF7B80)
    self.assertIsNone(application_sa_mirror_for_f181("8965F1208999"))
    self.assertEqual(set(APPLICATION_SA_MIRRORS), {"8965B4512000", "8965H1202000", "8965F1208000"})

  def test_application_sa_plan_is_read_only_memory_id_geometry(self):
    plan = application_sa_recovery_plan("8965B4512000")
    self.assertTrue(plan["supported"])
    self.assertEqual(plan["address"], "0xfebf7be0")
    self.assertEqual(plan["memory_id"], RAM_ID)
    self.assertEqual(plan["size"], 16)
    self.assertEqual(plan["expected_root"], APPLICATION_SA_ROOT_EXPECTED.hex())
    self.assertEqual(
      memory_id_request_data(plan["memory_id"], int(plan["address"], 16), plan["size"]),
      bytes.fromhex("1501febf7be010"),
    )

    unknown = application_sa_recovery_plan("8965Z9999999")
    self.assertFalse(unknown["supported"])
    self.assertEqual(unknown["address"], "")
    self.assertIsNone(unknown["memory_id"])
    self.assertEqual(unknown["expected_root"], "")

  def test_exact_request_uses_raw_uds_service_and_requires_exact_length(self):
    service = SimpleNamespace(READ_MEMORY_BY_ADDRESS=0x23)
    uds = FakeUds(b"A" * 16)
    self.assertEqual(read_memory_with_id(uds, service, RAM_ID, BOOT_PAYLOAD_KEY_RESIDUE, 16), b"A" * 16)
    self.assertEqual(uds.calls, [(0x23, None, bytes.fromhex("1501febf2d0810"))])

    short = FakeUds(b"A" * 15)
    with self.assertRaises(ValueError):
      read_memory_with_id(short, service, RAM_ID, BOOT_PAYLOAD_KEY_RESIDUE, 16)


if __name__ == "__main__":
  unittest.main()
