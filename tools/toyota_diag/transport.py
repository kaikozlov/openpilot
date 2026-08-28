"""Live Toyota diagnostic transports.

When pandad is stopped, use direct Panda ownership and the exact Camry-validated
ELM327 setup. When pandad is already running, reuse openpilot's can/sendcan
messaging path only if the live Panda is already in the validated non-OBD
ELM327 diagnostic state with controls disallowed. The managed path never
changes Panda safety itself.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from subprocess import CalledProcessError, check_output
from typing import Any

from opendbc.car.structs import CarParams
from opendbc.car.uds import IsoTpMessage, UdsClient

from tools.toyota_diag import registry
from tools.toyota_diag.registry import Profile

ELM327_PARAM_NORMAL = 1
MANAGED_READY_TIMEOUT = 1.0
SENDCAN_WARMUP = 0.15


def pandad_running() -> bool:
  for command in (["pidof", "pandad"], ["pgrep", "-x", "pandad"]):
    try:
      check_output(command)
      return True
    except CalledProcessError as e:
      if e.returncode == 1:
        return False
      raise
    except FileNotFoundError:
      continue
  raise SystemExit("cannot verify Panda ownership: neither pidof nor pgrep is available")


def managed_diagnostic_ready(panda_states: Any, profile: Profile) -> bool:
  """Return whether sendcan is in the exact fail-closed state used for F33 diagnostics."""
  if profile.bus != 0 or len(panda_states) != 1:
    return False
  state = panda_states[0]
  return (state.safetyModel == CarParams.SafetyModel.elm327 and
          state.safetyParam == ELM327_PARAM_NORMAL and
          not state.controlsAllowed)


def _wait_panda_states(messaging_module, timeout: float = MANAGED_READY_TIMEOUT):
  sm = messaging_module.SubMaster(["pandaStates"])
  deadline = time.monotonic() + timeout
  states = sm["pandaStates"]
  while not len(states) and time.monotonic() < deadline:
    sm.update(100)
    states = sm["pandaStates"]
  return sm, states


def _managed_refusal(panda_states: Any, profile: Profile) -> str:
  if profile.bus != 0:
    return f"profile Panda bus {profile.bus} is not validated for managed diagnostics"
  if len(panda_states) != 1:
    return f"expected one Panda for managed diagnostics, got {len(panda_states)}"
  state = panda_states[0]
  return "".join((
    "pandad is running but Panda is not in diagnostic-safe ELM327/param1 state ",
    f"(safetyModel={state.safetyModel}, safetyParam={state.safetyParam}, controlsAllowed={state.controlsAllowed}); ",
    "stop openpilot/manager for direct Panda diagnostics",
  ))


class ManagedCanReceiver:
  """Receive-only CAN adapter backed by pandad's public `can` service."""

  def __init__(self, *, messaging_module=None) -> None:
    if messaging_module is None:
      import openpilot.cereal.messaging as messaging_module
    self.messaging = messaging_module
    self.can_sock = messaging_module.sub_sock("can", conflate=False, timeout=100)

  def can_recv(self) -> list[tuple[int, bytes, int]]:
    frames: list[tuple[int, bytes, int]] = []
    for event in self.messaging.drain_sock(self.can_sock, wait_for_one=False):
      frames.extend((msg.address, bytes(msg.dat), msg.src) for msg in event.can)
    return frames


class ManagedPandaAdapter(ManagedCanReceiver):
  """Minimal Panda-compatible CAN adapter backed by openpilot can/sendcan sockets."""

  def __init__(self, profile: Profile, *, messaging_module=None, can_serializer=None,
               sleep: Callable[[float], None] = time.sleep) -> None:
    if messaging_module is None:
      import openpilot.cereal.messaging as messaging_module
    if can_serializer is None:
      from openpilot.selfdrive.pandad import can_list_to_can_capnp
      can_serializer = can_list_to_can_capnp

    super().__init__(messaging_module=messaging_module)
    self.profile = profile
    self.can_serializer = can_serializer
    self.sendcan = messaging_module.pub_sock("sendcan")
    self.sm, _ = _wait_panda_states(messaging_module)
    self._assert_ready()

    # ZMQ slow-joiner guard; openpilot's own VIN/FW path relies on the same
    # publisher/subscriber connection settling before the first diagnostic TX.
    sleep(SENDCAN_WARMUP)

  def _assert_ready(self) -> None:
    self.sm.update(0)
    states = self.sm["pandaStates"]
    if not managed_diagnostic_ready(states, self.profile):
      raise SystemExit(_managed_refusal(states, self.profile))

  def can_send(self, address: int, data: bytes, bus: int, timeout=None) -> None:
    del timeout
    self._assert_ready()
    payload = self.can_serializer([(address, bytes(data), bus)], msgtype="sendcan")
    self.sendcan.send(payload)

  def can_clear(self, flags: int) -> None:
    del flags
    self.messaging.drain_sock(self.can_sock, wait_for_one=False)


def status(profile: Profile, *, messaging_module=None) -> dict[str, Any]:
  """Describe the transport a live command could use without transmitting anything."""
  if not pandad_running():
    return {
      "pandad_running": False,
      "mode": "direct-panda",
      "ready": True,
      "detail": "pandad stopped; next live command will claim Panda directly (hardware not probed)",
    }

  if messaging_module is None:
    import openpilot.cereal.messaging as messaging_module
  _, states = _wait_panda_states(messaging_module)
  ready = managed_diagnostic_ready(states, profile)
  return {
    "pandad_running": True,
    "mode": "managed-sendcan" if ready else "blocked",
    "ready": ready,
    "detail": "pandad already owns Panda in validated diagnostic-safe ELM327/param1 state" if ready else _managed_refusal(states, profile),
  }


def passive_receiver():
  """Return a receive-only CAN source without changing Panda safety."""
  if pandad_running():
    return ManagedCanReceiver()
  from panda import Panda  # lazy: offline commands must not import Panda
  return Panda()


def connect(profile: Profile):
  if pandad_running():
    return ManagedPandaAdapter(profile)

  from panda import Panda  # lazy: offline commands must not import Panda
  panda = Panda()
  # Param 0 is the exact live-validated Camry DTC-clear setup. The current
  # profile uses bus 0, so the bus-1 OBD multiplex side effect is irrelevant.
  panda.set_safety_mode(CarParams.SafetyModel.elm327, 0)
  return panda


def uds_client_factory(panda, profile: Profile, timeouts: registry.CommTimeouts | None = None) -> Callable[[int], UdsClient]:
  def factory(address: int) -> UdsClient:
    return UdsClient(panda, address, bus=profile.bus,
                     timeout=timeouts.uds_timeout if timeouts is not None else profile.uds_timeout,
                     response_pending_timeout=timeouts.response_pending_timeout if timeouts is not None else profile.uds_response_pending_timeout)
  return factory


def raw_isotp(client: UdsClient, request: bytes) -> bytes:
  """Send arbitrary ISO-TP diagnostic bytes and return the raw response payload.

  Unlike UdsClient._uds_request this intentionally does not coerce the service byte
  through SERVICE_TYPE, so Toyota/proprietary service IDs remain reachable.
  """
  msg = IsoTpMessage(client._can_client, timeout=client.timeout)
  msg.send(request)
  response_pending = False
  while True:
    timeout = client.response_pending_timeout if response_pending else client.timeout
    response, _ = msg.recv(timeout)
    if response is None:
      continue
    response_pending = len(response) >= 3 and response[0] == 0x7F and response[2] == 0x78
    if response_pending:
      continue
    return response
