"""Exclusive-Panda transport for live Toyota diagnostics."""
from __future__ import annotations

from collections.abc import Callable
from subprocess import CalledProcessError, check_output

from opendbc.car.structs import CarParams
from opendbc.car.uds import IsoTpMessage, UdsClient

from tools.toyota_diag.registry import Profile


def require_exclusive_panda() -> None:
  try:
    check_output(["pidof", "pandad"])
  except CalledProcessError as e:
    if e.returncode == 1:
      return
    raise
  except FileNotFoundError as e:
    raise SystemExit("cannot verify exclusive Panda access: pidof unavailable") from e
  raise SystemExit("pandad is running; stop openpilot/manager before live Toyota diagnostics")


def connect():
  require_exclusive_panda()
  from panda import Panda  # lazy: offline commands must not import Panda
  panda = Panda()
  panda.set_safety_mode(CarParams.SafetyModel.elm327, 0)
  return panda


def uds_client_factory(panda, profile: Profile) -> Callable[[int], UdsClient]:
  def factory(address: int) -> UdsClient:
    return UdsClient(panda, address, bus=profile.bus, timeout=profile.uds_timeout,
                     response_pending_timeout=profile.uds_response_pending_timeout)
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
