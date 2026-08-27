"""Fail-closed runtime config parser for exact-F33 development lateral."""
from __future__ import annotations

from dataclasses import dataclass
import json


@dataclass(frozen=True)
class ToyotaTSS3DevelopmentConfig:
  f181: str
  b6_template: bytes
  cadence_frames: int
  gate2_bypass_validated: bool
  exclusive_b6_authority_validated: bool


def parse_toyota_tss3_development_config(raw: bytes | None) -> ToyotaTSS3DevelopmentConfig:
  cfg = json.loads(raw.decode()) if raw is not None else {}
  template = bytes.fromhex(cfg["b6_template_hex"])
  if len(template) != 28:
    raise ValueError("b6_template_hex must encode exactly 28 bytes")

  cadence_frames = int(cfg["cadence_frames"])
  if not 1 <= cadence_frames <= 100:
    raise ValueError("cadence_frames must be 1..100 control frames")

  f181 = str(cfg["f181"])
  if f181 != "8965F3307000":
    raise ValueError("f181 must be exact development target 8965F3307000")

  gate2_validated = cfg["gate2_bypass_validated"] is True
  exclusive_authority = cfg["exclusive_b6_authority_validated"] is True
  if not gate2_validated:
    raise ValueError("gate2_bypass_validated must be true after live causal proof")
  if not exclusive_authority:
    raise ValueError("exclusive_b6_authority_validated must be true after relay/source proof")

  return ToyotaTSS3DevelopmentConfig(
    f181=f181,
    b6_template=template,
    cadence_frames=cadence_frames,
    gate2_bypass_validated=gate2_validated,
    exclusive_b6_authority_validated=exclusive_authority,
  )
