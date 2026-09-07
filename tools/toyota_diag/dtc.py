"""Toyota DTC scan/clear primitives over logical diagnostic endpoints.

Physical UDS operations preserve Toyota logical addressing (`request ID + optional
address extension`). Functional legislated OBD remains the standard 0x7DF path.
Vehicle/category selection and responder sets come from the resolved Toyota profile.
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

from tools.toyota_diag.registry import EcuSpec, decode_status_bits

FUNCTIONAL_OBD_REQUEST_ADDR = 0x7DF


def parse_dtc_response(data: bytes) -> list[tuple[str, int]]:
  if not data:
    return []
  payload = data[1:]  # first byte is status-availability mask
  if len(payload) % 4:
    raise ValueError(f"malformed DTC response length {len(data)}")
  return [(get_dtc_num_as_str(payload[i:i + 3]), payload[i + 3]) for i in range(0, len(payload), 4)]


DtcTarget = EcuSpec | tuple[int, str] | int


def _target_parts(target: DtcTarget) -> tuple[int, int | None, str]:
  if isinstance(target, EcuSpec):
    return target.address, target.sub_addr, target.name
  if isinstance(target, int):
    return target, None, f"ECU {target:#05x}"
  return int(target[0]), None, str(target[1])


def _result_key(target: DtcTarget):
  return target if isinstance(target, EcuSpec) else _target_parts(target)[0]


def read_ecu_dtcs(client_factory: Callable[[int, int | None], UdsClient], target: DtcTarget) -> list[tuple[str, int]] | None:
  address, sub_addr, _ = _target_parts(target)
  try:
    data = client_factory(address, sub_addr).read_dtc_information(DTC_REPORT_TYPE.DTC_BY_STATUS_MASK, DTC_STATUS_MASK_TYPE.ALL)
    return parse_dtc_response(data)
  except (MessageTimeoutError, NegativeResponseError):
    return None


def scan(client_factory: Callable[[int, int | None], UdsClient], ecus: Sequence[DtcTarget], fault_status_mask: int, *,
         show_all: bool = False, echo: Callable[[str], None] = print) \
        -> tuple[dict[DtcTarget, list[tuple[str, int]]], list[tuple[DtcTarget, str, int]]]:
  """Walk logical ECU endpoints in order; return (responding records, fault-status records)."""
  responding: dict[DtcTarget, list[tuple[str, int]]] = {}
  faults: list[tuple[DtcTarget, str, int]] = []
  for target in ecus:
    address, sub_addr, name = _target_parts(target)
    endpoint = f"{address:#05x}" + (f"/{sub_addr:#04x}" if sub_addr is not None else "")
    records = read_ecu_dtcs(client_factory, target)
    if records is None:
      if show_all:
        echo(f"{endpoint} {name}: no response")
      continue
    result_key = _result_key(target)
    responding[result_key] = records
    active = [(code, status) for code, status in records if status & fault_status_mask]
    faults.extend((result_key, code, status) for code, status in active)
    if show_all or active:
      echo(f"{endpoint} {name}: {len(records)} DTC record(s), {len(active)} fault-status record(s)")
      for code, status in active:
        echo(f"  {code} status={status:#04x} {' '.join(decode_status_bits(status))}")
  return responding, faults


def clear_physical_uds(client_factory: Callable[[int, int | None], UdsClient], responders: Mapping[DtcTarget, str], *,
                       echo: Callable[[str], None] = print) -> None:
  echo("\nphysical UDS clear (14 FF FF FF):")
  for target, name in responders.items():
    address, sub_addr, _ = _target_parts(target)
    endpoint = f"{address:#05x}" + (f"/{sub_addr:#04x}" if sub_addr is not None else "")
    try:
      client_factory(address, sub_addr).clear_diagnostic_information(DTC_GROUP_TYPE.ALL)
      echo(f"  {endpoint} {name}: cleared")
    except NegativeResponseError as e:
      echo(f"  {endpoint} {name}: not supported ({e})")
    except MessageTimeoutError:
      echo(f"  {endpoint} {name}: timeout")


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
