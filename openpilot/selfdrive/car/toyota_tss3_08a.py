"""Exact-F33 0x08A request-plane wire constants and handoff helpers."""
from __future__ import annotations

from collections.abc import Callable

from opendbc.car.can_definitions import CanData

NATIVE_08A_ADDR = 0x08A
SECOC_SYNC_ADDR = 0x00F
ADMIN_ADDR = 0x777
UPSTREAM_BUS = 2
SYNC_BUS = 0
DOWNSTREAM_BUS = 0
ADMIN_BUS = 1
STABLE_NATIVE_FRAMES = 8
PANDA_RETURNED_OFFSET = 0x80
PANDA_REJECTED_OFFSET = 0xC0

SendCan = Callable[[list[CanData]], None]


def decode_sync(data: bytes) -> tuple[int, int]:
  if len(data) != 8:
    raise ValueError("0x00F sync frame must be 8 bytes")
  trip = int.from_bytes(data[0:2], "big")
  reset = (data[2] << 12) | (data[3] << 4) | (data[4] >> 4)
  return trip, reset


def make_admin(arm: bool) -> CanData:
  return CanData(ADMIN_ADDR, bytes((7, 0xC9, 0xA8, int(arm), 0, 0, 0, 0)), ADMIN_BUS)
