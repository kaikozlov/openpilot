"""Live Toyota diagnostic transports.

When pandad is stopped, use direct Panda ownership in Panda's ordinary ELM327
diagnostic safety mode while preserving normal-harness bus routing by default;
OBD bus-1 multiplexing is an explicit caller option. When pandad is already
running, reuse openpilot's can/sendcan messaging path if the live Panda is already
in ELM327 safety. The managed path never changes Panda safety itself; Panda's
ELM327 TX hook remains the diagnostic-address/frame enforcement boundary.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from subprocess import CalledProcessError, check_output
from typing import Any

from opendbc.car.can_definitions import CanData
from opendbc.car.structs import CarParams
from opendbc.car.uds import IsoTpMessage, UdsClient

from tools.toyota_diag import registry
from tools.toyota_diag.registry import Profile

MANAGED_READY_TIMEOUT = 1.0
SENDCAN_WARMUP = 0.15
QUERY_RECV_WAIT = 0.1


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
  """Return whether pandad's Panda is already in the diagnostic safety model."""
  del profile
  if len(panda_states) != 1:
    return False
  return panda_states[0].safetyModel == CarParams.SafetyModel.elm327


def _wait_panda_states(messaging_module, timeout: float = MANAGED_READY_TIMEOUT):
  sm = messaging_module.SubMaster(["pandaStates"])
  deadline = time.monotonic() + timeout
  states = sm["pandaStates"]
  while not len(states) and time.monotonic() < deadline:
    sm.update(100)
    states = sm["pandaStates"]
  return sm, states


def _managed_refusal(panda_states: Any, profile: Profile) -> str:
  del profile
  if len(panda_states) != 1:
    return f"expected one Panda for managed diagnostics, got {len(panda_states)}"
  state = panda_states[0]
  return "".join((
    "pandad is running but Panda is not in ELM327 diagnostic safety ",
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


def status(profile: Profile, *, messaging_module=None, obd_multiplexing: bool = False) -> dict[str, Any]:
  """Describe the transport a live command could use without transmitting anything."""
  if not pandad_running():
    return {
      "pandad_running": False,
      "mode": "direct-panda",
      "ready": True,
      "detail": ("pandad stopped; next live command will claim Panda directly "
                 + f"with {'OBD-port' if obd_multiplexing else 'normal-harness'} bus-1 routing (hardware not probed)"),
    }

  if messaging_module is None:
    import openpilot.cereal.messaging as messaging_module
  _, states = _wait_panda_states(messaging_module)
  ready = managed_diagnostic_ready(states, profile)
  return {
    "pandad_running": True,
    "mode": "managed-sendcan" if ready else "blocked",
    "ready": ready,
    "detail": "pandad already owns Panda in ELM327 diagnostic safety" if ready else _managed_refusal(states, profile),
  }


def passive_receiver():
  """Return a receive-only CAN source without changing Panda safety."""
  if pandad_running():
    return ManagedCanReceiver()
  from panda import Panda  # lazy: offline commands must not import Panda
  return Panda()


def connect(profile: Profile, *, obd_multiplexing: bool = False):
  if pandad_running():
    return ManagedPandaAdapter(profile)

  from panda import Panda  # lazy: offline commands must not import Panda
  panda = Panda()
  # Panda ELM327 param 0 remaps logical bus 1 onto the OBD-II pins; param 1
  # preserves normal harness routing. This is installation state, not Toyota
  # vehicle/profile metadata, so the generic default is deliberately no remap.
  panda.set_safety_mode(CarParams.SafetyModel.elm327, 0 if obd_multiplexing else 1)
  return panda


def can_query_callbacks(panda, *, wait_timeout: float = QUERY_RECV_WAIT):
  """Adapt direct Panda/managed-sendcan transport to openpilot's standard CAN query callbacks."""
  def can_recv(wait_for_one: bool = False) -> list[list[CanData]]:
    deadline = time.monotonic() + wait_timeout
    while True:
      frames = panda.can_recv()
      if frames:
        return [[CanData(address, bytes(data), bus) for address, data, bus in frames]]
      if not wait_for_one or time.monotonic() >= deadline:
        return []
      time.sleep(0.001)

  def can_send(messages: list[CanData]) -> None:
    for message in messages:
      panda.can_send(message.address, bytes(message.dat), message.src)

  return can_recv, can_send


def uds_client_factory(panda, profile: Profile, timeouts: registry.CommTimeouts | None = None,
                       *, validate_profile_routes: bool = True) -> Callable[..., UdsClient]:
  bus = registry.require_panda_bus(profile)

  def factory(address: int, sub_addr: int | None = None, *, rx_addr: int | None = None,
              rx_sub_addr: int | None = None) -> UdsClient:
    if validate_profile_routes:
      matches = [ecu for ecu in profile.ecus if ecu.route_resolved and ecu.endpoint == (address, sub_addr)]
      if matches and not any(ecu.uds_transport_supported for ecu in matches):
        kinds = ", ".join(sorted({ecu.transport_kind or "unclassified" for ecu in matches}))
        raise registry.RegistryError(
          f"Toyota route {address:#x}{f'/{sub_addr:#x}' if sub_addr is not None else ''} uses {kinds}; "
          + "the current Panda UDS transport does not implement that controller")
    kwargs = {
      "bus": bus,
      "sub_addr": sub_addr,
      "timeout": timeouts.uds_timeout if timeouts is not None else profile.uds_timeout,
      "response_pending_timeout": timeouts.response_pending_timeout if timeouts is not None else profile.uds_response_pending_timeout,
    }
    if rx_addr is not None:
      kwargs["rx_addr"] = rx_addr
    if rx_sub_addr is not None:
      kwargs["rx_sub_addr"] = rx_sub_addr
    return UdsClient(panda, address, **kwargs)
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
