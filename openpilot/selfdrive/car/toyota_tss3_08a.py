"""Development-only exact-F33 transparent ID0 0x08A replacement.

Phase 0 deliberately does not synthesize Toyota application data, freshness, or
MACs. Panda blocks a fresh native FRC 0x08A before it reaches the chassis side;
this proxy immediately retransmits that exact 32-byte frame from bus 0.

The purpose is to qualify source suppression + comma-origin publication before
introducing the already-proven EPS MAC oracle into the production loop.
"""
from __future__ import annotations

from collections.abc import Callable

from opendbc.car import structs
from opendbc.car.can_definitions import CanData
from opendbc.car.toyota.values import CAR, ToyotaSafetyFlags

NATIVE_08A_ADDR = 0x08A
SECOC_SYNC_ADDR = 0x00F
ADMIN_ADDR = 0x777
UPSTREAM_BUS = 2
DOWNSTREAM_BUS = 0
ADMIN_BUS = 1
STABLE_NATIVE_FRAMES = 8
PANDA_RETURNED_OFFSET = 0x80
PANDA_REJECTED_OFFSET = 0xC0

GearShifter = structs.CarState.GearShifter
SendCan = Callable[[list[CanData]], None]


def decode_sync(data: bytes) -> tuple[int, int]:
  if len(data) != 8:
    raise ValueError("0x00F sync frame must be 8 bytes")
  trip = int.from_bytes(data[0:2], "big")
  reset = (data[2] << 12) | (data[3] << 4) | (data[4] >> 4)
  return trip, reset


def make_admin(arm: bool, next_b26: int = 0) -> CanData:
  if not 0 <= next_b26 <= 0x3F:
    raise ValueError("B26 generation must be 0..63")
  action = 1 if arm else 0
  b26 = next_b26 if arm else 0
  return CanData(ADMIN_ADDR, bytes((7, 0xC9, 0xA8, action, b26, 0, 0, 0)), ADMIN_BUS)


def enable_in_car_params(CP: structs.CarParams, *, requested: bool, is_release: bool) -> bool:
  enabled = requested and not is_release and CP.carFingerprint == CAR.TOYOTA_CAMRY_TSS3 and not CP.passive
  if enabled:
    CP.safetyConfigs[0].safetyParam |= ToyotaSafetyFlags.TSS3_08A_HOST.value
  return enabled


class ToyotaTss3Id0Proxy:
  """Exact-frame proxy for the first bounded F33 0x08A sender phase."""

  def __init__(self, send_can: SendCan):
    self._send_can = send_can
    self.active = False
    self.sync_valid = False
    self.trip_counter: int | None = None
    self.reset_counter: int | None = None
    self.active_reset_counter: int | None = None
    self.last_b26: int | None = None
    self.next_b26: int | None = None
    self.stable_native_frames = 0
    self.arm_pending = False
    self.arm_pending_b26: int | None = None
    self.arm_pending_reset: int | None = None
    self.arm_missed_target = False
    self.arm_admin_data: bytes | None = None
    self.arm_count = 0
    self.proxy_count = 0
    self.release_count = 0
    self.rejected_proxy_count = 0

  @staticmethod
  def _stationary_park(CS: structs.CarState) -> bool:
    return bool(CS.standstill and CS.gearShifter == GearShifter.park)

  def _release(self) -> None:
    if self.active:
      self._send_can([make_admin(False)])
      self.release_count += 1
    self.active = False
    self.active_reset_counter = None
    self.next_b26 = None
    self.arm_pending = False
    self.arm_pending_b26 = None
    self.arm_pending_reset = None
    self.arm_missed_target = False
    self.arm_admin_data = None
    self.stable_native_frames = 0
    self.last_b26 = None

  def _observe_sync(self, data: bytes) -> None:
    try:
      trip, reset = decode_sync(data)
    except ValueError:
      return
    changed = self.sync_valid and (trip != self.trip_counter or reset != self.reset_counter)
    self.trip_counter, self.reset_counter = trip, reset
    self.sync_valid = True
    if changed:
      # Panda safety independently releases ownership on RESET_CNT change. Mirror
      # that state locally; stock 0x08A forwarding resumes while we re-qualify.
      self.active = False
      self.active_reset_counter = None
      self.next_b26 = None
      self.arm_pending = False
      self.arm_pending_b26 = None
      self.arm_pending_reset = None
      self.arm_missed_target = False
      self.arm_admin_data = None
      self.stable_native_frames = 0
      self.last_b26 = None

  def _observe_native(self, data: bytes, CS: structs.CarState) -> None:
    if len(data) != 32 or not self.sync_valid:
      self._release()
      return

    target_id = data[21] & 0x3F
    b26 = data[26] & 0x3F
    fv4 = data[28] >> 4
    reset_low2 = fv4 & 0x3
    if target_id != 0 or self.reset_counter is None or reset_low2 != (self.reset_counter & 0x3):
      self._release()
      return

    if not self._stationary_park(CS):
      self._release()
      return

    if self.arm_pending and self.arm_pending_b26 == b26:
      # If the target generation reaches the host before Panda confirms the arm
      # TX, we cannot know whether that source frame was forwarded or blocked.
      # Mark this handoff unusable and fail back to stock on confirmation.
      self.arm_missed_target = True

    if self.active:
      if self.active_reset_counter != self.reset_counter or self.next_b26 is None or b26 != self.next_b26:
        self._release()
        return
      # This is the exact fresh frame Panda just suppressed upstream. Do not
      # alter any application/freshness/MAC bit in phase 0.
      self._send_can([CanData(NATIVE_08A_ADDR, data, DOWNSTREAM_BUS)])
      self.proxy_count += 1
      self.last_b26 = b26
      self.next_b26 = (b26 + 1) & 0x3F
      return

    if self.last_b26 is not None and b26 == ((self.last_b26 + 1) & 0x3F):
      self.stable_native_frames += 1
    else:
      self.stable_native_frames = 1
    self.last_b26 = b26

    if self.stable_native_frames >= STABLE_NATIVE_FRAMES and not self.arm_pending:
      next_b26 = (b26 + 1) & 0x3F
      admin = make_admin(True, next_b26)
      self._send_can([admin])
      self.arm_pending = True
      self.arm_pending_b26 = next_b26
      self.arm_pending_reset = self.reset_counter
      self.arm_missed_target = False
      self.arm_admin_data = admin.dat

  def _observe_tx_echo(self, address: int, data: bytes, src: int) -> None:
    if address == ADMIN_ADDR and self.arm_pending and data == self.arm_admin_data:
      if src == ADMIN_BUS + PANDA_RETURNED_OFFSET:
        if self.arm_missed_target or self.arm_pending_reset != self.reset_counter:
          # Safety may already be active; explicitly release it rather than
          # starting from a generation whose forwarding disposition is unknown.
          self._send_can([make_admin(False)])
          self.release_count += 1
          self.active = False
          self.stable_native_frames = 0
          self.last_b26 = None
        else:
          self.active = True
          self.active_reset_counter = self.arm_pending_reset
          self.next_b26 = self.arm_pending_b26
          self.arm_count += 1
        self.arm_pending = False
        self.arm_pending_b26 = None
        self.arm_pending_reset = None
        self.arm_missed_target = False
        self.arm_admin_data = None
      elif src == ADMIN_BUS + PANDA_REJECTED_OFFSET:
        self.arm_pending = False
        self.arm_pending_b26 = None
        self.arm_pending_reset = None
        self.arm_missed_target = False
        self.arm_admin_data = None
        self.stable_native_frames = 0
        self.last_b26 = None
    elif address == NATIVE_08A_ADDR and src == DOWNSTREAM_BUS + PANDA_REJECTED_OFFSET:
      self.rejected_proxy_count += 1
      self._release()

  def update(self, can_list: list, CS: structs.CarState) -> None:
    """Consume the same decoded raw CAN batches passed to CarInterface.update."""
    if self.active and not self._stationary_park(CS):
      self._release()

    for _, packets in can_list:
      for address, dat, src in packets:
        address_i, src_i = int(address), int(src)
        data = bytes(dat)
        if src_i >= PANDA_RETURNED_OFFSET:
          self._observe_tx_echo(address_i, data, src_i)
          continue
        if src_i == UPSTREAM_BUS and address_i == SECOC_SYNC_ADDR:
          self._observe_sync(data)
        elif src_i == UPSTREAM_BUS and address_i == NATIVE_08A_ADDR:
          self._observe_native(data, CS)

  def shutdown(self) -> None:
    self._release()
