#!/usr/bin/env python3
"""Bounded read/observe-only probe for the 8965B4512000 CAN 0x7F7 XCP channel.

Firmware analysis recovered an unauthenticated XCP-shaped application channel on
CAN 0x7F7/0x7F8. Standard SHORT_UPLOAD (0xF4) can read permitted LocalRAM and the
configured DAQ subset (E3/E2/E1/E0/DE) can sample selected LocalRAM bytes into
DTOs on 0x7F8.

This TSK probe deliberately implements only CONNECT, F4, and volatile DAQ
configuration. It does NOT implement E4 page copy, F6 SET_MTA, F5 UPLOAD, F0
DOWNLOAD, EC MODIFY_BITS, or any source-memory write. CONNECT reachability may be
measured on an unknown Toyota EPS, but address reads and DAQ configuration are
performed only when F181 contains the exact analyzed application ID
8965B4512000.
"""
from __future__ import annotations

import subprocess
import time
from collections.abc import Iterable
from dataclasses import dataclass

from tsk.lib.diagnostic_route import configure_elm327, discover_eps_route_with_routing, route_fields
from tsk.lib.dump_dataflash import ADDR
from tsk.lib.dump_diag import CANDIDATE_BUSES
from tsk.lib.env import is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor

REQUEST_ID = 0x7F7
RESPONSE_ID = 0x7F8
FRAME_SIZE = 8
EXACT_APPLICATION_ID = b"8965B4512000"

LOCALRAM_START = 0xFEBE0000
LOCALRAM_END_EXCLUSIVE = 0xFEC00000
LOCALRAM_EXCLUSIONS = (
  (0xFEBE0000, 0xFEBE3800),
  (0xFEBE5030, 0xFEBE529C),
  (0xFEBF0288, 0xFEBF13CC),
  (0xFEBF4958, 0xFEBF4B34),
  (0xFEBF6C00, 0xFEBF78E0),
)
MAX_SHORT_UPLOAD = 7
LIST_INDEX = 0
EVENT_INDEX = 0
PRESCALER = 1
ENTRIES_PER_ODT = 7
ODTS_PER_LIST = 4
MAX_DAQ_ENTRIES = ENTRIES_PER_ODT * ODTS_PER_LIST
CONNECT_REQUEST = bytes.fromhex("ff00000000000000")


class XcpObserverError(RuntimeError):
  pass


@dataclass(frozen=True)
class ObservationProfile:
  name: str
  description: str
  addresses: tuple[int, ...]


PROFILES: dict[str, ObservationProfile] = {
  "actuation-discriminator": ObservationProfile(
    "actuation-discriminator",
    "d/q-reference words plus staged TSG3 comparison bytes",
    (0xFEBE6D28, 0xFEBE6D29, 0xFEBE6D2A, 0xFEBE6D2B, 0xFEBE38A2, 0xFEBE38A4, 0xFEBE38A6),
  ),
  "diagnostic-control-state": ObservationProfile(
    "diagnostic-control-state",
    "volatile state associated with WDBI 2012/2013/2014",
    (0xFEBEB18F, 0xFEBEB18E, 0xFEBEB434, 0xFEBEB435, 0xFEBEB3EE, 0xFEBEB3EC, 0xFEBEB3E7),
  ),
  "routine-lifecycle-state": ObservationProfile(
    "routine-lifecycle-state",
    "RoutineControl one-shot flags and lifecycle group states",
    (0xFEBE8157, 0xFEBE8158, 0xFEBE8159, 0xFEBEB454, 0xFEBEB455, 0xFEBEB456, 0xFEBEB2D5),
  ),
  "async-ba-state": ObservationProfile(
    "async-ba-state",
    "async-operation queue plus BA authorization marker/countdown",
    (0xFEBE828C, 0xFEBE8290, 0xFEBE8291, 0xFEBE8292, 0xFEBE8293, 0xFEBE5F27, 0xFEBE5F28),
  ),
  "ba-operational-state": ObservationProfile(
    "ba-operational-state",
    "SID-BA lifecycle, alternate-speed, and inhibit state",
    (0xFEBEB112, 0xFEBEB113, 0xFEBEB116, 0xFEBEB117, 0xFEBEB118, 0xFEBEE894, 0xFEBEE895),
  ),
}


def _noop(**kwargs) -> None:
  pass


def validate_localram_read(address: int, length: int) -> None:
  if length <= 0:
    raise XcpObserverError("LocalRAM read length must be positive")
  if not 0 <= address <= 0xFFFFFFFF:
    raise XcpObserverError("LocalRAM address must fit in 32 bits")
  end = address + length
  if end > 0x100000000:
    raise XcpObserverError("LocalRAM range wraps 32 bits")
  if address < LOCALRAM_START or end > LOCALRAM_END_EXCLUSIVE:
    raise XcpObserverError("LocalRAM read is outside FEBE0000..FEBFFFFF")
  for low, high in LOCALRAM_EXCLUSIONS:
    if address < high and end > low:
      raise XcpObserverError(f"LocalRAM read intersects protected interval 0x{low:08X}..0x{high - 1:08X}")


def short_upload_request(address: int, length: int) -> bytes:
  if not 1 <= length <= MAX_SHORT_UPLOAD:
    raise XcpObserverError("SHORT_UPLOAD length must be 1..7")
  validate_localram_read(address, length)
  return bytes((0xF4, length, 0, 0)) + address.to_bytes(4, "little")


def _u16le(value: int) -> bytes:
  if not 0 <= value <= 0xFFFF:
    raise XcpObserverError("DAQ index must fit in 16 bits")
  return value.to_bytes(2, "little")


def clear_daq_list_request() -> bytes:
  return bytes((0xE3, 0)) + _u16le(LIST_INDEX) + b"\x00" * 4


def set_daq_ptr_request(odt: int, entry: int = 0) -> bytes:
  if not 0 <= odt < ODTS_PER_LIST:
    raise XcpObserverError("ODT index must be 0..3")
  if not 0 <= entry < ENTRIES_PER_ODT:
    raise XcpObserverError("DAQ entry index must be 0..6")
  return bytes((0xE2, 0)) + _u16le(LIST_INDEX) + bytes((odt, entry, 0, 0))


def write_daq_request(address: int) -> bytes:
  validate_localram_read(address, 1)
  return bytes((0xE1, 0xFF, 0x01, 0x00)) + address.to_bytes(4, "little")


def set_daq_list_mode_request() -> bytes:
  return bytes((0xE0, 0)) + _u16le(LIST_INDEX) + _u16le(EVENT_INDEX) + bytes((PRESCALER, 0))


def start_stop_daq_list_request(start: bool) -> bytes:
  return bytes((0xDE, 1 if start else 0)) + _u16le(LIST_INDEX) + b"\x00" * 4


def validate_addresses(addresses: Iterable[int]) -> tuple[int, ...]:
  values = tuple(int(a) for a in addresses)
  if not values:
    raise XcpObserverError("at least one observation address is required")
  if len(values) > MAX_DAQ_ENTRIES:
    raise XcpObserverError(f"one DAQ list supports at most {MAX_DAQ_ENTRIES} byte entries")
  if len(set(values)) != len(values):
    raise XcpObserverError("duplicate observation addresses are not allowed")
  for address in values:
    validate_localram_read(address, 1)
  return values


def layout(addresses: Iterable[int]) -> tuple[tuple[int, ...], ...]:
  values = validate_addresses(addresses)
  return tuple(tuple(values[i:i + ENTRIES_PER_ODT]) for i in range(0, len(values), ENTRIES_PER_ODT))


def configuration_requests(addresses: Iterable[int]) -> tuple[tuple[str, bytes], ...]:
  requests: list[tuple[str, bytes]] = [("connect", CONNECT_REQUEST), ("clear_daq_list", clear_daq_list_request())]
  for odt, group in enumerate(layout(addresses)):
    requests.append((f"set_daq_ptr_{odt}", set_daq_ptr_request(odt)))
    for entry, address in enumerate(group):
      requests.append((f"write_daq_{odt}_{entry}", write_daq_request(address)))
  requests.extend((
    ("set_daq_list_mode", set_daq_list_mode_request()),
    ("start_daq_list", start_stop_daq_list_request(True)),
  ))
  return tuple(requests)


def _recv_control(panda, *, bus: int, timeout: float, operation: str) -> bytes:
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    for row in panda.can_recv():
      if len(row) < 4:
        continue
      address, data, row_bus = int(row[0]), bytes(row[-2]), int(row[-1])
      if row_bus != bus or address != RESPONSE_ID:
        continue
      if len(data) != FRAME_SIZE:
        raise XcpObserverError(f"{operation} response DLC is {len(data)}, expected 8")
      # DTO PIDs share 0x7F8 once DAQ is running. Command responses are FF/FE.
      if data[0] in (0xFE, 0xFF):
        return data
    time.sleep(0.001)
  raise XcpObserverError(f"timed out waiting for {operation} response on 0x{RESPONSE_ID:03X}")


def _exchange(panda, *, bus: int, request: bytes, timeout: float, operation: str) -> bytes:
  if len(request) != FRAME_SIZE:
    raise XcpObserverError("XCP requests must be exactly eight bytes")
  panda.can_recv()
  panda.can_send(REQUEST_ID, request, bus)
  response = _recv_control(panda, bus=bus, timeout=timeout, operation=operation)
  if response[0] == 0xFE:
    raise XcpObserverError(f"{operation} returned XCP error 0x{response[1]:02X}")
  if response[0] != 0xFF:
    raise XcpObserverError(f"{operation} returned unexpected PID 0x{response[0]:02X}")
  return response


def short_upload(panda, *, bus: int, address: int, length: int, timeout: float) -> bytes:
  response = _exchange(
    panda, bus=bus, request=short_upload_request(address, length), timeout=timeout,
    operation=f"short_upload 0x{address:08X}",
  )
  if any(response[1 + length:]):
    raise XcpObserverError("SHORT_UPLOAD response has nonzero bytes beyond requested data")
  return response[1:1 + length]


def configure_daq(panda, *, bus: int, addresses: Iterable[int], timeout: float) -> None:
  start_sent = False
  try:
    for operation, request in configuration_requests(addresses):
      if operation == "start_daq_list":
        start_sent = True
      response = _exchange(panda, bus=bus, request=request, timeout=timeout, operation=operation)
      if operation == "start_daq_list" and response[1] != 0:
        raise XcpObserverError(f"START_DAQ_LIST first PID is 0x{response[1]:02X}, expected 0")
  except Exception:
    if start_sent:
      try:
        stop_daq(panda, bus=bus, timeout=timeout)
      except Exception:
        pass
    raise


def stop_daq(panda, *, bus: int, timeout: float) -> None:
  _exchange(panda, bus=bus, request=start_stop_daq_list_request(False), timeout=timeout, operation="stop_daq_list")


def decode_dto(data: bytes, addresses: Iterable[int]) -> dict | None:
  if len(data) != FRAME_SIZE:
    raise XcpObserverError("DAQ DTO must be exactly eight bytes")
  if data[0] in (0xFE, 0xFF):
    return None
  groups = layout(addresses)
  pid = int(data[0])
  if pid >= len(groups):
    return None
  return {
    "pid": pid,
    "raw": data.hex(),
    "values": [
      {"address": f"0x{address:08x}", "value": int(data[index + 1])}
      for index, address in enumerate(groups[pid])
    ],
  }


def capture_dto(panda, *, bus: int, addresses: Iterable[int], duration: float, max_frames: int) -> list[dict]:
  if not 0 < duration <= 10:
    raise XcpObserverError("capture duration must be >0 and <=10 seconds")
  if not 1 <= max_frames <= 2048:
    raise XcpObserverError("max frame count must be 1..2048")
  values = validate_addresses(addresses)
  deadline = time.monotonic() + duration
  captured: list[dict] = []
  started = time.monotonic()
  while time.monotonic() < deadline and len(captured) < max_frames:
    for row in panda.can_recv():
      if len(row) < 4:
        continue
      address, data, row_bus = int(row[0]), bytes(row[-2]), int(row[-1])
      if row_bus != bus or address != RESPONSE_ID or len(data) != FRAME_SIZE:
        continue
      decoded = decode_dto(data, values)
      if decoded is None:
        continue
      decoded["t_ms"] = round((time.monotonic() - started) * 1000.0, 3)
      captured.append(decoded)
      if len(captured) >= max_frames:
        break
    time.sleep(0.001)
  return captured


def probe_xcp(profile: str = "actuation-discriminator", progress_cb=None,
              capture_seconds: float = 1.5, max_frames: int = 512) -> dict:
  """Measure XCP reachability; observe DAQ only on exact 8965B4512000."""
  if not is_agnos():
    raise NotAGNOSError
  if profile not in PROFILES:
    raise XcpObserverError(f"unknown XCP profile: {profile}")
  cb = progress_cb or _noop

  subprocess.run(["pkill", "-9", "-f", "manager.py"], check=False)
  subprocess.run(["pkill", "-9", "-f", "pandad"], check=False)
  time.sleep(2)

  result = {
    "status": "failed", "panda": "", "eps_bus": -1, "f181": "", "f181_hex": "",
    "profile": profile, "profile_description": PROFILES[profile].description,
    "xcp_request_id": f"0x{REQUEST_ID:03x}", "xcp_response_id": f"0x{RESPONSE_ID:03x}",
    "connect_response": "", "snapshot": [], "frames": [], "message": "",
    "write_commands_implemented": False,
  }
  try:
    panda = TSKExtractor._connect_panda()
    try:
      version = panda.get_version()
      result["panda"] = version.decode(errors="replace") if isinstance(version, (bytes, bytearray)) else str(version)
    except Exception:
      result["panda"] = "unknown"
  except Exception as e:
    result["message"] = f"Connect failed: {type(e).__name__}: {e}"
    return result

  route = discover_eps_route_with_routing(panda, CANDIDATE_BUSES, preferred_tx=ADDR)
  if route is None or route["tx_bus"] != route["rx_bus"]:
    result.update(status="unreachable", message="No same-bus EPS route was identified before the XCP probe.")
    return result
  result.update(**route_fields(route))
  bus = int(route["tx_bus"])
  configure_elm327(panda, int(route.get("elm327_param", 1)))
  identity = bytes.fromhex(str(route.get("identity", ""))) if route.get("identity") else b""
  result["f181_hex"] = identity.hex()
  result["f181"] = "".join(chr(c) if 32 <= c < 127 else "." for c in identity)

  cb(step="connect", last="CAN 0x7F7 CONNECT")
  try:
    response = _exchange(panda, bus=bus, request=CONNECT_REQUEST, timeout=0.35, operation="connect")
  except XcpObserverError as e:
    result.update(status="unreachable", message=f"No usable XCP CONNECT response on the EPS route: {e}")
    return result
  result["connect_response"] = response.hex()

  if EXACT_APPLICATION_ID not in identity:
    result.update(
      status="reachable",
      message=" ".join((
        "CAN 0x7F7/0x7F8 answered CONNECT, but F181 is not the exact analyzed 8965B4512000",
        "application. TSK stopped before address reads or DAQ configuration.",
      )),
    )
    return result

  addresses = PROFILES[profile].addresses
  cb(step="snapshot", last="bounded F4 LocalRAM reads")
  for address in addresses:
    value = short_upload(panda, bus=bus, address=address, length=1, timeout=0.35)
    result["snapshot"].append({"address": f"0x{address:08x}", "value": value[0]})

  cb(step="daq", last=f"configure {profile}")
  configured = False
  try:
    configure_daq(panda, bus=bus, addresses=addresses, timeout=0.35)
    configured = True
    cb(step="capture", last="capture 0x7F8 DAQ DTOs")
    result["frames"] = capture_dto(
      panda, bus=bus, addresses=addresses, duration=capture_seconds, max_frames=max_frames,
    )
  finally:
    if configured:
      try:
        stop_daq(panda, bus=bus, timeout=0.35)
      except Exception as e:
        result["cleanup_error"] = f"{type(e).__name__}: {e}"

  result["status"] = "observed"
  result["message"] = " ".join((
    f"XCP CONNECT, bounded F4 reads, and volatile DAQ observation succeeded for {profile};",
    f"captured {len(result['frames'])} DTO frame(s). No XCP source-memory write command was implemented.",
  ))
  return result
