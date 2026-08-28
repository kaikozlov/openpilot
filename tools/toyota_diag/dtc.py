"""Exact 2026 Camry DTC scan/clear semantics behind the unified Toyota CLI.

Every frame, UDS call, ordering, print, and exit-code decision is preserved:

  * physical UDS 0x14 FF FF FF for ECUs that support ClearDiagnosticInformation
  * functional legislated OBD Mode 04 on 0x7DF (exact validated frame 0104000000000000)
  * final DTC status sweep; nonzero fault-status bits under the profile mask fail the command

The ECU set, names, guards, and legislated responders come from the registry.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence

from opendbc.car.uds import (
  DTC_GROUP_TYPE,
  DTC_REPORT_TYPE,
  DTC_STATUS_MASK_TYPE,
  MessageTimeoutError,
  NegativeResponseError,
  UdsClient,
  get_dtc_num_as_str,
)

from tools.toyota_diag.registry import Guard, decode_status_bits

FUNCTIONAL_OBD_REQUEST_ADDR = 0x7DF


def parse_dtc_response(data: bytes) -> list[tuple[str, int]]:
  if not data:
    return []
  payload = data[1:]  # first byte is status-availability mask
  if len(payload) % 4:
    raise ValueError(f"malformed DTC response length {len(data)}")
  return [(get_dtc_num_as_str(payload[i:i + 3]), payload[i + 3]) for i in range(0, len(payload), 4)]


def read_ecu_dtcs(client_factory: Callable[[int], UdsClient], address: int) -> list[tuple[str, int]] | None:
  try:
    data = client_factory(address).read_dtc_information(DTC_REPORT_TYPE.DTC_BY_STATUS_MASK, DTC_STATUS_MASK_TYPE.ALL)
    return parse_dtc_response(data)
  except (MessageTimeoutError, NegativeResponseError):
    return None


def scan(client_factory: Callable[[int], UdsClient], ecus: Sequence[tuple[int, str]], fault_status_mask: int, *,
         show_all: bool = False, echo: Callable[[str], None] = print) \
        -> tuple[dict[int, list[tuple[str, int]]], list[tuple[int, str, int]]]:
  """Walk ECUs in order; return (responding records, fault-status records)."""
  responding: dict[int, list[tuple[str, int]]] = {}
  faults: list[tuple[int, str, int]] = []
  for address, name in ecus:
    records = read_ecu_dtcs(client_factory, address)
    if records is None:
      if show_all:
        echo(f"{address:#05x} {name}: no response")
      continue
    responding[address] = records
    active = [(dtc, status) for dtc, status in records if status & fault_status_mask]
    faults.extend((address, dtc, status) for dtc, status in active)
    if show_all or active:
      echo(f"{address:#05x} {name}: {len(records)} DTC record(s), {len(active)} fault-status record(s)")
      for dtc, status in active:
        echo(f"  {dtc} status={status:#04x} {' '.join(decode_status_bits(status))}")
  return responding, faults


def verify_vehicle_identity(client_factory: Callable[[int], UdsClient], guards: Sequence[tuple[int, str, Guard]], *,
                            echo: Callable[[str], None] = print) -> None:
  """Refuse to continue unless every identity guard's DID contains its expected needle."""
  for address, name, guard in guards:
    try:
      value = client_factory(address).read_data_by_identifier(guard.did)
    except Exception as e:
      raise SystemExit(f"refusing: could not verify {name} DID {guard.did:#06x} at {address:#05x}: {e}") from e
    if guard.contains not in value:
      raise SystemExit(f"refusing: {name} DID {guard.did:#06x} does not contain {guard.contains_hex!r}: {value!r}")
    echo(f"vehicle guard: {name} DID {guard.did:#06x} contains {guard.contains_hex}")


def clear_physical_uds(client_factory: Callable[[int], UdsClient], responders: Mapping[int, str], *,
                       echo: Callable[[str], None] = print) -> None:
  echo("\nphysical UDS clear (14 FF FF FF):")
  for address, name in responders.items():
    try:
      client_factory(address).clear_diagnostic_information(DTC_GROUP_TYPE.ALL)
      echo(f"  {address:#05x} {name}: cleared")
    except NegativeResponseError as e:
      echo(f"  {address:#05x} {name}: not supported ({e})")
    except MessageTimeoutError:
      echo(f"  {address:#05x} {name}: timeout")


def functional_obd_request(panda, mode: int, payload: bytes = b"", responders: frozenset[int] | set[int] = frozenset(),
                           bus: int = 0, window: float = 1.0, *, positive_prefix: bytes | None = None,
                           echo: Callable[[str], None] = print) -> set[int]:
  """Send a functional legislated OBD request on 0x7DF and collect positive responders.

  Standard CAN framing: single-frame PCI, [len] [mode+0x40 ...]. Mode 04 with no
  payload reproduces the exact live-validated frame 0104000000000000.
  """
  request = bytes([len(payload) + 1, mode]) + payload
  panda.can_clear(0xFFFF)
  panda.can_send(FUNCTIONAL_OBD_REQUEST_ADDR, request.ljust(8, b"\x00"), bus)

  positive_mode = mode + 0x40
  positive: set[int] = set()
  deadline = time.monotonic() + window
  while time.monotonic() < deadline:
    for address, data, recv_bus in panda.can_recv():
      matches = data.startswith(positive_prefix) if positive_prefix is not None else (len(data) >= 2 and data[0] >= 1 and data[1] == positive_mode)
      if recv_bus == bus and address in responders and matches:
        positive.add(address)
    if positive == responders:
      break

  echo(f"\nfunctional OBD Mode {mode:#04x} (0x7DF):")
  for address in sorted(responders):
    echo(f"  {address:#05x}: {'positive ' + hex(positive_mode) if address in positive else 'NO POSITIVE RESPONSE'}")
  return positive


def functional_obd_mode04(panda, responders: frozenset[int] | set[int], bus: int = 0, *,
                          echo: Callable[[str], None] = print) -> set[int]:
  # Exact live-validated standard CAN frame: functional request 0x7DF, one-byte Mode 04 payload.
  return functional_obd_request(panda, 0x04, b"", responders, bus, 1.0, positive_prefix=b"\x01\x44", echo=echo)
