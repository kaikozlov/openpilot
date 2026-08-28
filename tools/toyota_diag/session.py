"""Recovered Techstream session lifecycle over the existing diagnostic transports.

A `DiagnosticSession` binds one ECU on an already-connected transport (direct Panda
or managed pandad via `transport.connect`) and models the recovered lifecycle:

- CommSet timeouts: `registry.commset_timeouts(profile, operation_row)` resolves
  per-operation > per-profile > live-validated defaults, and the session's client
  factory honors them when constructed from a Panda.
- current-P5 TMS-077 SendProc: entering the extended session is the recovered D1
  (default `10 01`) then D2 (extended `10 03`) sequence, never a direct `10 03`.
  When the metadata declares the `22 F1 86` session poll, the ECU's reported
  session state is preferred and an already-extended ECU skips the transition.
  Cleanup sends D1 (`10 01`).
- Keepalive/session polling: the current-P5 registry metadata declares a poll
  (`22 F1 86` -> `62 F1 86` session byte) or tester-present cadence.
- Deterministic cleanup: context exit returns the ECU to the default session
  after extended-session operation, best-effort, never masking an in-flight
  exception. `__enter__` itself never transmits; transitions are gated by the
  executor's explicit execute acknowledgement.

Unrecognized or malformed lifecycle metadata fails closed (`LifecycleUnsupported`
/ `RegistryError`); no session byte, SendProc step, or keepalive kind is inferred.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from opendbc.car.uds import MessageTimeoutError, NegativeResponseError, UdsClient

from tools.toyota_diag import dtc, registry
from tools.toyota_diag.registry import EcuSpec, Profile

SUPPORTED_SESSION_GENERATIONS = frozenset({"current-p5"})
SESSION_DID_DEFAULT = 0xF186  # active diagnostic session, the current-P5 22 F1 86 poll
KEEPALIVE_TESTER_PRESENT = "tester_present"
KEEPALIVE_SESSION_DID_POLL = "session_did_poll"
SUPPORTED_KEEPALIVE_KINDS = frozenset({KEEPALIVE_TESTER_PRESENT, KEEPALIVE_SESSION_DID_POLL})
DIAGNOSTIC_SESSION_CONTROL_SERVICE = 0x10


class LifecycleError(RuntimeError):
  """A recovered session lifecycle could not be followed."""


class LifecycleUnsupported(LifecycleError):
  """The registry does not supply recoverable metadata for this lifecycle step."""


@dataclass(frozen=True)
class KeepaliveSpec:
  kind: str
  interval_s: float
  did: int = SESSION_DID_DEFAULT


@dataclass(frozen=True)
class SessionLifecycle:
  generation: str
  default_session: int
  extended_session: int
  enter_sequence: tuple[bytes, ...]  # TMS-077 SendProc: D1 default reset then D2 extended
  return_default_request: bytes  # D1 cleanup
  keepalive: KeepaliveSpec | None


def _session_byte(value: Any, what: str) -> int:
  session = registry.parse_int(value, what)
  if not 0 < session <= 0xFF:
    raise registry.RegistryError(f"{what}: session byte out of range: {value!r}")
  return session


def _dsc_request(value: Any, what: str) -> tuple[bytes, int]:
  """Validate an exact `10 XX` DiagnosticSessionControl request; return (request, session)."""
  request = registry.parse_bytes(value, what)
  if len(request) != 2 or request[0] != DIAGNOSTIC_SESSION_CONTROL_SERVICE:
    raise LifecycleUnsupported(f"{what} {request.hex()} is not an exact two-byte 10 XX session request")
  return request, request[1]


def parse_lifecycle(profile: Profile) -> SessionLifecycle | None:
  """Validate recovered `profile.session_control` metadata; None when the registry supplies none.

  Raises RegistryError for malformed metadata and LifecycleUnsupported for metadata
  this runtime does not know how to follow. Both fail closed.
  """
  raw = profile.session_control
  if raw is None:
    return None

  generation = raw.get("generation")
  if not isinstance(generation, str) or not generation:
    raise registry.RegistryError("session_control.generation: expected a non-empty string")
  if generation not in SUPPORTED_SESSION_GENERATIONS:
    supported = ", ".join(sorted(SUPPORTED_SESSION_GENERATIONS))
    raise LifecycleUnsupported(f"session_control generation {generation!r} is not supported (supported: {supported})")

  for key in ("default_session", "extended_session", "return_default"):
    if key not in raw:
      raise registry.RegistryError(f"session_control.{key}: required for generation {generation!r}")
  default_session = _session_byte(raw["default_session"], "session_control.default_session")
  extended_session = _session_byte(raw["extended_session"], "session_control.extended_session")
  return_default, return_session = _dsc_request(raw["return_default"], "session_control.return_default")
  if return_session != default_session:
    raise LifecycleUnsupported(
      f"session_control.return_default {return_default.hex()} is not the declared default session {default_session:#04x} transition; refused")

  enter_sequence = _parse_enter_sequence(raw, default_session, extended_session)

  keepalive = None
  if raw.get("keepalive") is not None:
    spec = raw["keepalive"]
    if not isinstance(spec, dict):
      raise registry.RegistryError("session_control.keepalive: expected an object")
    kind = spec.get("kind")
    if kind not in SUPPORTED_KEEPALIVE_KINDS:
      supported = ", ".join(sorted(SUPPORTED_KEEPALIVE_KINDS))
      raise LifecycleUnsupported(f"session_control.keepalive kind {kind!r} is not supported (supported: {supported})")
    if "interval_s" not in spec:
      raise registry.RegistryError("session_control.keepalive.interval_s: required")
    interval = registry.parse_seconds(spec["interval_s"], "session_control.keepalive.interval_s")
    did = SESSION_DID_DEFAULT
    if kind == KEEPALIVE_SESSION_DID_POLL:
      did = registry.parse_hex_key(str(spec.get("did", f"0x{SESSION_DID_DEFAULT:04X}")),
                                   "session_control.keepalive.did")
      _validate_session_poll_wire(spec, did)
    keepalive = KeepaliveSpec(kind=kind, interval_s=interval, did=did)

  return SessionLifecycle(
    generation=generation,
    default_session=default_session,
    extended_session=extended_session,
    enter_sequence=enter_sequence,
    return_default_request=return_default,
    keepalive=keepalive,
  )


def _validate_session_poll_wire(spec: dict[str, Any], did: int) -> None:
  """Reject recovered session-poll wire hints that disagree with the declared DID.

  UdsClient validates the `22`/`62` service and DID echo at runtime; this catches
  inconsistent metadata at parse time instead of silently ignoring those fields.
  """
  did_bytes = did.to_bytes(2, "big")
  expected = {"request": bytes((0x22,)) + did_bytes, "positive_prefix": bytes((0x62,)) + did_bytes}
  for key, want in expected.items():
    if spec.get(key) is None:
      continue
    got = registry.parse_bytes(spec[key], f"session_control.keepalive.{key}")
    if got != want:
      raise registry.RegistryError(
        f"session_control.keepalive.{key} {got.hex()} disagrees with the declared poll DID {did:04X} (want {want.hex()})")



def _parse_enter_sequence(raw: dict[str, Any], default_session: int, extended_session: int) -> tuple[bytes, ...]:
  """TMS-077 SendProc entry sequence; `enter_sequence` preferred, legacy `enter_extended` tolerated.

  The legacy single-request shape carries no D1 step of its own, so it is expanded
  to (return_default, enter_extended) — the recovered D1/D2 SendProc — rather than
  flattening to a direct extended transition.
  """
  if raw.get("enter_sequence") is not None:
    rows = raw["enter_sequence"]
    if not isinstance(rows, list) or not rows:
      raise registry.RegistryError("session_control.enter_sequence: expected a non-empty list of 10 XX requests")
    sequence: list[bytes] = []
    for index, value in enumerate(rows):
      request, session = _dsc_request(value, f"session_control.enter_sequence[{index}]")
      if session not in (default_session, extended_session):
        what = f"session_control.enter_sequence[{index}] targets session {session:#04x}"
        raise LifecycleUnsupported(
          f"{what}, neither the declared default {default_session:#04x} nor extended {extended_session:#04x}; refused")
      sequence.append(request)
    d1 = bytes((0x10, default_session)).hex()
    d2 = bytes((0x10, extended_session)).hex()
    if len(sequence) != 2 or sequence[0][1] != default_session or sequence[-1][1] != extended_session:
      raise LifecycleUnsupported(f"session_control.enter_sequence must reproduce the TMS-077 D1/D2 SendProc exactly: {d1} then {d2}")
    return tuple(sequence)

  if raw.get("enter_extended") is None:
    raise registry.RegistryError(
      "session_control.enter_sequence: required to describe the TMS-077 D1/D2 SendProc for this generation")
  enter_extended, enter_session = _dsc_request(raw["enter_extended"], "session_control.enter_extended")
  if enter_session != extended_session:
    raise LifecycleUnsupported(
      f"session_control.enter_extended {enter_extended.hex()} is not the declared extended session {extended_session:#04x} transition; refused")
  return_default, _ = _dsc_request(raw["return_default"], "session_control.return_default")
  return (return_default, enter_extended)


class DiagnosticSession:
  """Per-ECU recovered session lifecycle; deterministic default-session cleanup on exit."""

  def __init__(self, profile: Profile, ecu: EcuSpec, *, panda=None,
               client_factory: Callable[[int], UdsClient] | None = None,
               operation_row: dict[str, Any] | None = None) -> None:
    if (panda is None) == (client_factory is None):
      raise ValueError("pass exactly one of panda or client_factory")
    self.profile = profile
    self.ecu = ecu
    self.timeouts = registry.commset_timeouts(profile, operation_row)
    self.cleanup_errors: list[str] = []
    self._lifecycle: SessionLifecycle | None | None = None  # parsed lazily; None means absent
    self._active_session: int | None = None  # session byte when this session established it
    self._extended = False  # operating in the extended session (transitioned or confirmed by poll)
    self._clients: dict[int, UdsClient] = {}
    if client_factory is not None:
      self._factory = client_factory  # caller-owned; timeouts are advisory for prebuilt clients
    else:
      from tools.toyota_diag import transport  # lazy: offline use never imports transport
      self._factory = transport.uds_client_factory(panda, profile, self.timeouts)

  # -- transport surface ---------------------------------------------------------
  def client(self, address: int | None = None) -> UdsClient:
    addr = self.ecu.address if address is None else address
    if addr not in self._clients:
      self._clients[addr] = self._factory(addr)
    return self._clients[addr]

  def guard(self, *, echo: Callable[[str], None] = print) -> None:
    """Run the profile identity guard (e.g. EPS F181) before any mutation."""
    dtc.verify_vehicle_identity(lambda addr: self.client(addr), self.profile.guard_specs(), echo=echo)

  # -- lifecycle -------------------------------------------------------------------
  @property
  def lifecycle(self) -> SessionLifecycle | None:
    if self._lifecycle is None:
      self._lifecycle = parse_lifecycle(self.profile)
    return self._lifecycle

  @property
  def active_session(self) -> int | None:
    return self._active_session

  @property
  def extended(self) -> bool:
    return self._extended

  def poll_active_session(self) -> int:
    """Read the active-session DID (current-P5 `22 F1 86` -> `62 F1 86`) and return the session byte."""
    value = self.client().read_data_by_identifier(self._session_did())
    if not value:
      raise LifecycleError(f"DID {self._session_did():#06x} returned no session byte")
    return value[0]

  def enter_extended(self, *, acknowledge: bool = False) -> None:
    """TMS-077 SendProc entry into the extended session; requires an explicit acknowledgement.

    When the metadata declares the session-DID poll, the ECU's reported state is
    preferred: an ECU already reporting the extended session skips the D1/D2
    transition. Otherwise the recovered sequence (D1 `10 01` then D2 `10 03`) is
    sent verbatim. Never a direct `10 03`.
    """
    if not acknowledge:
      raise LifecycleError("entering the extended session requires an explicit acknowledgement")
    lifecycle = self.lifecycle
    if lifecycle is None:
      raise LifecycleUnsupported("registry supplies no recovered session_control metadata; cannot enter the extended session")
    if self._active_session == lifecycle.extended_session:
      return
    poll = self._declared_session_poll(lifecycle)
    if poll is not None:
      try:
        value = self.client().read_data_by_identifier(poll.did)
      except (MessageTimeoutError, NegativeResponseError):
        value = None  # the full SendProc below is valid regardless of the current state
      if value is not None and len(value) >= 1:
        if value[0] == lifecycle.extended_session:
          self._active_session = lifecycle.extended_session
          self._extended = True  # already in D2 state; cleanup still normalizes to D1
          return
    try:
      for request in lifecycle.enter_sequence:
        self.client().diagnostic_session_control(request[1])
    except BaseException:
      # The ECU may have transitioned before a response was lost; undo deterministically.
      self._record_cleanup("default-session undo after failed SendProc", self._undo_transition)
      raise
    self._active_session = lifecycle.extended_session
    self._extended = True

  def restore_default(self) -> None:
    """D1 cleanup: return the ECU to the recovered default session."""
    lifecycle = self.lifecycle
    if lifecycle is None:
      raise LifecycleUnsupported("registry supplies no recovered session_control metadata; cannot restore the default session")
    self.client().diagnostic_session_control(lifecycle.default_session)
    self._active_session = None
    self._extended = False

  def keepalive(self) -> None:
    """One recovered keepalive step: tester present or the `22 F1 86` session-DID poll."""
    lifecycle = self.lifecycle
    if lifecycle is None or lifecycle.keepalive is None:
      raise LifecycleUnsupported("registry supplies no recovered keepalive metadata")
    spec = lifecycle.keepalive
    if spec.kind == KEEPALIVE_TESTER_PRESENT:
      self.client().tester_present()
      return
    value = self.client().read_data_by_identifier(spec.did)
    if not value:
      raise LifecycleError(f"keepalive poll DID {spec.did:#06x} returned no session byte")
    if self._active_session is not None and value[0] != self._active_session:
      raise LifecycleError(
        f"keepalive poll: ECU reports session {value[0]:#04x}, expected {self._active_session:#04x}")

  # -- context manager ---------------------------------------------------------------
  def __enter__(self) -> DiagnosticSession:
    return self  # no transmission: transitions are gated by the explicit execute acknowledgement

  def __exit__(self, *exc_info) -> bool:
    self.close()
    return False

  def close(self) -> None:
    """Deterministic cleanup: D1 (`10 01`) after extended-session operation, best-effort."""
    if self._extended:
      self._record_cleanup("default-session restore", self.restore_default)

  # -- helpers -------------------------------------------------------------------------
  def _session_did(self) -> int:
    lifecycle = self.lifecycle
    if lifecycle is not None and lifecycle.keepalive is not None:
      return lifecycle.keepalive.did
    return SESSION_DID_DEFAULT

  def _declared_session_poll(self, lifecycle: SessionLifecycle) -> KeepaliveSpec | None:
    if lifecycle.keepalive is not None and lifecycle.keepalive.kind == KEEPALIVE_SESSION_DID_POLL:
      return lifecycle.keepalive
    return None

  def _undo_transition(self) -> None:
    lifecycle = self.lifecycle
    if lifecycle is not None:
      self.client().diagnostic_session_control(lifecycle.default_session)
      self._active_session = None
      self._extended = False

  def _record_cleanup(self, what: str, action: Callable[[], None]) -> None:
    try:
      action()
    except BaseException as e:  # cleanup must never mask the in-flight failure
      self.cleanup_errors.append(f"{what} failed: {e!r}")
