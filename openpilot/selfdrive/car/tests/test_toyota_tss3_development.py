import json
import unittest

from openpilot.selfdrive.car.toyota_tss3_dev import parse_toyota_tss3_development_config


class TestToyotaTSS3DevelopmentConfig(unittest.TestCase):
  VALID = {
    "f181": "8965F3307000",
    "b6_template_hex": bytes(range(28)).hex(),
    "cadence_frames": 2,
    "gate2_bypass_validated": True,
    "exclusive_b6_authority_validated": True,
  }

  def parse(self, cfg):
    return parse_toyota_tss3_development_config(json.dumps(cfg).encode())

  def test_valid_config(self):
    cfg = self.parse(self.VALID)
    self.assertEqual(cfg.f181, "8965F3307000")
    self.assertEqual(cfg.b6_template, bytes(range(28)))
    self.assertEqual(cfg.cadence_frames, 2)
    self.assertTrue(cfg.gate2_bypass_validated)
    self.assertTrue(cfg.exclusive_b6_authority_validated)

  def test_missing_or_unvalidated_fields_fail_closed(self):
    bad = [
      {},
      self.VALID | {"b6_template_hex": "00" * 27},
      self.VALID | {"f181": "8965F3307001"},
      self.VALID | {"cadence_frames": 0},
      self.VALID | {"cadence_frames": 4},
      self.VALID | {"gate2_bypass_validated": False},
      self.VALID | {"exclusive_b6_authority_validated": False},
    ]
    for cfg in bad:
      with self.subTest(cfg=cfg), self.assertRaises((KeyError, TypeError, ValueError)):
        self.parse(cfg)


if __name__ == "__main__":
  unittest.main()
