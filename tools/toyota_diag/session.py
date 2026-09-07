"""Recovered Techstream session lifecycle over the existing diagnostic transports.

A `DiagnosticSession` binds one ECU on an already-connected transport (direct Panda
or managed pandad via `transport.connect`) and models the recovered lifecycle:

- CommSet timeouts: `registry.commset_timeouts(profile, operation_row)` resolves
  per-operation > per-profile > live-validated defaults, and the session's client
  factory honors them when constructed from a Panda.
- Toyota category-local D1/D2 selectors define the session transition. The runtime
  executes their literal `10 XX` requests when that wire shape is present; it does
  not admit or reject categories by generation/family. When DD is a session poll,
  the ECU's reported state is preferred and an already-extended ECU skips D1/D2.
  Cleanup replays the selected category's D1 request.
- Keepalive/session polling comes from each category's actual DD selector. Current
  GTS categories use `22 F1 86`, other DID polls such as `22 D1 00`, or a `10 03`
  extended-session refresh; the runtime does not project the Camry/F186 form onto them.
- Deterministic cleanup: context exit returns the ECU to the default session
  after extended-session operation, best-effort, never masking an in-flight
  exception. `__enter__` itself never transmits; callers enter the Toyota lifecycle
  when their operation requires it.

Unrecognized or malformed lifecycle metadata fails closed (`LifecycleUnsupported`
/ `RegistryError`); no session byte, SendProc step, or keepalive kind is inferred.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from opendbc.car.uds import MessageTimeoutError, NegativeResponseError, UdsClient

from tools.toyota_diag import registry
from tools.toyota_diag.registry import EcuSpec, Profile

SESSION_DID_DEFAULT = 0xF186  # legacy/default value; category-local DD metadata overrides it
KEEPALIVE_TESTER_PRESENT = "tester_present"
KEEPALIVE_SESSION_DID_POLL = "session_did_poll"
KEEPALIVE_DID_POLL = "did_poll"
KEEPALIVE_EXTENDED_SESSION_REFRESH = "extended_session_refresh"
SUPPORTED_KEEPALIVE_KINDS = frozenset({
  KEEPALIVE_TESTER_PRESENT, KEEPALIVE_SESSION_DID_POLL, KEEPALIVE_DID_POLL, KEEPALIVE_EXTENDED_SESSION_REFRESH,
})
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


def parse_lifecycle(profile: Profile, ecu: EcuSpec | None = None) -> SessionLifecycle | None:
  """Validate recovered `profile.session_control` metadata; None when the registry supplies none.

  Raises RegistryError for malformed metadata and LifecycleUnsupported for metadata
  this runtime does not know how to follow. Both fail closed.
  """
  raw = profile.session_control
  if raw is None:
    return None

  # Universal bundles resolve D1/D2/DD independently per Toyota category. Use
  # the category row when it carries the new lifecycle classification; legacy
  # single-vehicle registries retain the historical global shape below.
  category_row = None
  if ecu is not None and ecu.category_id is not None:
    per_category = raw.get("per_category")
    candidate = per_category.get(str(ecu.category_id)) if isinstance(per_category, dict) else None
    if isinstance(candidate, dict) and ("session_executor_supported" in candidate or "lifecycle_supported" in candidate):
      category_row = candidate
      implemented = candidate.get("session_executor_supported", candidate.get("lifecycle_supported", True))
      if not implemented:
        return None

  generation = str(raw.get("kind") or raw.get("generation") or "toyota-category-selectors")

  if category_row is not None:
    d1 = category_row.get("default_session")
    d2 = category_row.get("extended_session")
    if not isinstance(d1, dict) or not isinstance(d2, dict):
      raise LifecycleUnsupported(f"category {ecu.category_id} does not publish complete D1/D2 session frames")
    d1_request, d1_session = _dsc_request(d1.get("send"), f"session_control.category[{ecu.category_id}].D1")
    d2_request, d2_session = _dsc_request(d2.get("send"), f"session_control.category[{ecu.category_id}].D2")
    declared_d1 = category_row.get("default_session_value")
    declared_d2 = category_row.get("extended_session_value")
    if declared_d1 is not None and registry.parse_int(declared_d1, "default_session_value") != d1_session:
      raise registry.RegistryError(f"category {ecu.category_id} D1 session value disagrees with send bytes")
    if declared_d2 is not None and registry.parse_int(declared_d2, "extended_session_value") != d2_session:
      raise registry.RegistryError(f"category {ecu.category_id} D2 session value disagrees with send bytes")
    raw = {
      **raw,
      "default_session": d1_session,
      "extended_session": d2_session,
      "enter_sequence": [d1_request.hex(), d2_request.hex()],
      "return_default": d1_request.hex(),
      "keepalive": category_row.get("keepalive"),
    }

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
    if kind in {KEEPALIVE_SESSION_DID_POLL, KEEPALIVE_DID_POLL}:
      did = registry.parse_hex_key(str(spec.get("did", f"0x{SESSION_DID_DEFAULT:04X}")),
                                   "session_control.keepalive.did")
      _validate_did_poll_wire(spec, did)
    elif kind == KEEPALIVE_EXTENDED_SESSION_REFRESH:
      request, session = _dsc_request(spec.get("request"), "session_control.keepalive.request")
      if request != bytes((DIAGNOSTIC_SESSION_CONTROL_SERVICE, extended_session)) or session != extended_session:
        raise LifecycleUnsupported(
          f"session_control.keepalive.request {request.hex()} is not the declared extended-session refresh")
    keepalive = KeepaliveSpec(kind=kind, interval_s=interval, did=did)

  return SessionLifecycle(
    generation=generation,
    default_session=default_session,
    extended_session=extended_session,
    enter_sequence=enter_sequence,
    return_default_request=return_default,
    keepalive=keepalive,
  )



def _validate_did_poll_wire(spec: dict[str, Any], did: int) -> None:
  """Reject recovered DID-poll wire hints that disagree with the declared DID.

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
               client_factory: Callable[[int, int | None], UdsClient] | None = None,
               operation_row: dict[str, Any] | None = None) -> None:
    if (panda is None) == (client_factory is None):
      raise ValueError("pass exactly one of panda or client_factory")
    self.profile = profile
    self.ecu = ecu
    self.timeouts = registry.commset_timeouts(profile, operation_row)
    # v4 also carries the raw Toyota CommSet row. Keep it visible to callers,
    # but do not reinterpret receive_timeout=1020 as seconds until Toyota's
    # CheckAndConvertRcvTimeOut conversion is recovered.
    self.session_commset = profile.session_commset(ecu)
    self.cleanup_errors: list[str] = []
    self._lifecycle: SessionLifecycle | None | None = None  # parsed lazily; None means absent
    self._active_session: int | None = None  # session byte when this session established it
    self._extended = False  # operating in the extended session (transitioned or confirmed by poll)
    self._clients: dict[tuple[int, int | None], UdsClient] = {}
    if client_factory is not None:
      self._factory = client_factory  # caller-owned; timeouts are advisory for prebuilt clients
    else:
      from tools.toyota_diag import transport  # lazy: offline use never imports transport
      self._factory = transport.uds_client_factory(panda, profile, self.timeouts)

  # -- transport surface ---------------------------------------------------------
  def client(self, address: int | None = None, sub_addr: int | None = None) -> UdsClient:
    addr = self.ecu.address if address is None else address
    extension = self.ecu.sub_addr if address is None and sub_addr is None else sub_addr
    endpoint = (addr, extension)
    if endpoint not in self._clients:
      self._clients[endpoint] = self._factory(addr, extension)
    return self._clients[endpoint]

  # -- lifecycle -------------------------------------------------------------------
  @property
  def lifecycle(self) -> SessionLifecycle | None:
    if self._lifecycle is None:
      self._lifecycle = parse_lifecycle(self.profile, self.ecu)
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

  def require_lifecycle_supported(self) -> SessionLifecycle:
    """Return this category's executable recovered lifecycle metadata."""
    lifecycle = self.lifecycle
    if lifecycle is None:
      raise LifecycleUnsupported("registry supplies no recovered session_control metadata")
    return lifecycle

  def enter_extended(self) -> None:
    """Enter the selected category's recovered D2 diagnostic session.

    When the metadata declares the session-DID poll, the ECU's reported state is
    preferred: an ECU already reporting the extended session skips the D1/D2
    transition. Otherwise the recovered sequence (D1 `10 01` then D2 `10 03`) is
    sent verbatim. No category/generation allowlist participates.
    """
    lifecycle = self.require_lifecycle_supported()
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
    """D1 cleanup: return the ECU to the category's recovered default session."""
    lifecycle = self.require_lifecycle_supported()
    self.client().diagnostic_session_control(lifecycle.default_session)
    self._active_session = None
    self._extended = False

  def keepalive(self) -> None:
    """Execute the category's recovered DD keepalive family."""
    lifecycle = self.require_lifecycle_supported()
    if lifecycle.keepalive is None:
      raise LifecycleUnsupported("registry supplies no recovered keepalive metadata")
    spec = lifecycle.keepalive
    if spec.kind == KEEPALIVE_TESTER_PRESENT:
      self.client().tester_present()
      return
    if spec.kind == KEEPALIVE_EXTENDED_SESSION_REFRESH:
      self.client().diagnostic_session_control(lifecycle.extended_session)
      return
    value = self.client().read_data_by_identifier(spec.did)
    if not value:
      raise LifecycleError(f"keepalive poll DID {spec.did:#06x} returned no data")
    if spec.kind == KEEPALIVE_SESSION_DID_POLL and self._active_session is not None and value[0] != self._active_session:
      raise LifecycleError(
        f"keepalive poll: ECU reports session {value[0]:#04x}, expected {self._active_session:#04x}")

  # -- context manager ---------------------------------------------------------------
  def __enter__(self) -> DiagnosticSession:
    return self  # no transmission; callers invoke Toyota's lifecycle when the operation requires it

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
