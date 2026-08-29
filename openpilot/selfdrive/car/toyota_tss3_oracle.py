from __future__ import annotations

from opendbc.car import structs
from opendbc.car.can_definitions import CanData
from opendbc.car.toyota.values import CAR, Ecu


FRC_TX = 0x792
FRC_RX = 0x79A
# The relay-correct 2026-08-27 post-repin DTC sweep directly reaches FRC 0x792
# on Panda logical bus 0. Toyota/GTS+ Central-Gateway "Bus 1" is a vehicle
# topology label, not a Panda bus number; do not conflate the two namespaces.
FRC_BUS = 0
FRC_LTA_DID = 0x1601
FRC_ACC_OPERATION_DID = 0x1914
F33_EPS_F181 = b"8965F3307000"
ELM327_PARAM_NORMAL = 1
POLL_INTERVAL_NS = 50_000_000  # alternating DIDs -> 10 Hz per DID
RESPONSE_STALE_NS = 2_000_000_000

# Both responses are ISO-TP single frames. Keep these literal: this helper is
# intentionally not a generic diagnostic client and cannot construct writes.
FRC_REQUESTS = {
  FRC_LTA_DID: bytes.fromhex("0322160100000000"),
  FRC_ACC_OPERATION_DID: bytes.fromhex("0322191400000000"),
}


def parse_frc_positive_response(data: bytes) -> int | None:
  """Return the DID for one exact positive single-frame oracle response."""
  if len(data) != 8 or data[1] != 0x62:
    return None

  did = (data[2] << 8) | data[3]
  if did == FRC_LTA_DID and data[0] == 0x07:
    return did
  if did == FRC_ACC_OPERATION_DID and data[0] == 0x05:
    return did
  return None


def exact_f33_camry(CP: structs.CarParams) -> bool:
  if CP.carFingerprint != CAR.TOYOTA_CAMRY_TSS3:
    return False
  return any(fw.ecu == Ecu.eps and F33_EPS_F181 in bytes(fw.fwVersion) for fw in CP.carFw)


def elm327_diagnostic_ready(panda_states) -> bool:
  """Require the one-Panda ELM327 runtime before emitting fixed RDBI frames."""
  if len(panda_states) != 1:
    return False
  ps = panda_states[0]
  return (ps.safetyModel == structs.CarParams.SafetyModel.elm327 and
          ps.safetyParam == ELM327_PARAM_NORMAL and
          not ps.controlsAllowed)


class ToyotaTSS3FrcOraclePoller:
  """Bounded exact-route 0x1601/0x1914 poller using card's sendcan publisher."""

  def __init__(self) -> None:
    self._started_ns = 0
    self._last_response_ns = {FRC_LTA_DID: 0, FRC_ACC_OPERATION_DID: 0}
    self._next_poll_ns = 0
    self._poll_index = 0
    self.stopped = False

  def observe(self, can_batches: list[list[CanData]], now_ns: int) -> None:
    for batch in can_batches:
      for msg in batch:
        if msg.src != FRC_BUS or msg.address != FRC_RX:
          continue
        did = parse_frc_positive_response(bytes(msg.dat))
        if did is not None:
          self._last_response_ns[did] = now_ns

  def poll(self, now_ns: int, *, diagnostics_allowed: bool) -> list[CanData]:
    """Return zero or one fixed RDBI frame for this card cycle."""
    if self.stopped or not diagnostics_allowed:
      return []

    if self._started_ns == 0:
      self._started_ns = now_ns
    else:
      for last_response_ns in self._last_response_ns.values():
        reference_ns = last_response_ns or self._started_ns
        if now_ns - reference_ns > RESPONSE_STALE_NS:
          self.stopped = True
          return []

    if now_ns < self._next_poll_ns:
      return []

    dids = (FRC_LTA_DID, FRC_ACC_OPERATION_DID)
    did = dids[self._poll_index]
    self._poll_index = (self._poll_index + 1) % len(dids)
    self._next_poll_ns = now_ns + POLL_INTERVAL_NS
    return [CanData(FRC_TX, FRC_REQUESTS[did], FRC_BUS)]


def configure_toyota_tss3_frc_oracle(params, is_release: bool,
                                      CP: structs.CarParams) -> ToyotaTSS3FrcOraclePoller | None:
  """Build the exact-F33 read-only oracle only behind an explicit dev opt-in."""
  if not params.get_bool("ToyotaTSS3FrcOracleCapture") or params.get_bool("ControlsReady"):
    return None
  if is_release or not CP.passive or not exact_f33_camry(CP):
    return None
  return ToyotaTSS3FrcOraclePoller()
