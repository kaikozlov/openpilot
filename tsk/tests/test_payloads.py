import hashlib
import unittest
from pathlib import Path

from tsk.lib.dump_dataflash import AUTORESET_PAYLOAD_SHA256, PAYLOAD_LOAD_SIZE, PAYLOAD_SHA256
from tsk.lib.env import DATAFLASH_AUTORESET_PAYLOAD_PATH, DATAFLASH_PAYLOAD_PATH, PAYLOAD_PATH


class TestPayloadFixtures(unittest.TestCase):
  def test_ram_dump_payload_fixture(self):
    payload = Path(PAYLOAD_PATH).read_bytes()
    self.assertEqual(len(payload), 0x1000)
    self.assertEqual(hashlib.sha256(payload).hexdigest(),
                     "d972d4bf432685217591768600a9abd7820d35b04a72270edc87074365356be2")

  def test_dataflash_payload_fixture(self):
    payload = Path(DATAFLASH_PAYLOAD_PATH).read_bytes()
    self.assertEqual(len(payload), PAYLOAD_LOAD_SIZE)
    self.assertEqual(hashlib.sha256(payload).hexdigest(), PAYLOAD_SHA256)

  def test_dataflash_autoreset_payload_fixture(self):
    payload = Path(DATAFLASH_AUTORESET_PAYLOAD_PATH).read_bytes()
    self.assertEqual(len(payload), PAYLOAD_LOAD_SIZE)
    self.assertEqual(AUTORESET_PAYLOAD_SHA256,
                     "bf62449f85648ea24708961749bf53f75f36083c01bcf54114d567da0e178725")
    self.assertEqual(hashlib.sha256(payload).hexdigest(), AUTORESET_PAYLOAD_SHA256)


if __name__ == "__main__":
  unittest.main()
