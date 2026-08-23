#!/usr/bin/env python3
"""Bounded read/observe-only probe for the 8965B4512000 CAN 0x7F7 XCP channel.

Firmware analysis recovered an unauthenticated XCP-shaped application channel on
CAN 0x7F7/0x7F8. Standard SHORT_UPLOAD (0xF4) can read permitted LocalRAM and the
configured DAQ subset (E3/E2/E1/E0/DE) can sample selected LocalRAM bytes into
DTOs on 0x7F8.

This TSK probe deliberately implements only CONNECT, F4, and volatile DAQ
configuration. It does NOT implement E4 page copy, F6 SET_MTA, F5 UPLOAD, F0
DOWNLOAD, EC MODIFY_BITS, or any source-memory write. Unknown Toyota EPS calibrations
may use the same bounded F4 reads and temporary DAQ configuration after CONNECT; the
8965B4512000-derived profile labels are then treated only as candidate addresses, not as
claims about what those bytes mean on the unknown calibration.
"""
from __future__ import annotations

import subprocess
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from tsk.lib.diagnostic_route import configure_elm327, discover_eps_route_with_routing, route_fields
from tsk.lib.dump_dataflash import ADDR
from tsk.lib.dump_diag import CANDIDATE_BUSES
from tsk.lib.env import is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor

SCHEMA = "tsk-xcp-daq-observer-v2"
REQUEST_ID = 0x7F7
RESPONSE_ID = 0x7F8
FRAME_SIZE = 8
EXACT_APPLICATION_ID = b"8965B4512000"

# Generic XCP write commands and the shadow-window page copy are deliberately
# absent from this observer. E4 is grouped with the writes because the copy
# mutates the 0xFEBF7C00 shadow window even though its CodeFlash source is fixed.
FORBIDDEN_COMMANDS = {
  0xF0: "DOWNLOAD is a generic write command and is not implemented",
  0xEC: "MODIFY_BITS is a generic write command and is not implemented",
  0xE4: "page copy mutates the shadow window (fixed source, still a mutation)",
}

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
  finding_ids: tuple[str, ...]


# These two SecOC state cells are intentionally absent from every XCP profile. The
# firmware LocalRAM range checker excludes them, so the read-only observer must never
# imply they are available through F4/DAQ. Command-5 remains behind its separate bench
# experiment rather than smuggling a write-capable path into this observer.
SECOC_XCP_EXCLUDED_CANDIDATES = (
  (0xFEBE51AA, "command-5 generated-result buffer inside FEBE5030..FEBE529B exclusion"),
  (0xFEBF13BE, "ICU-S job-completion polling word inside FEBF0288..FEBF13CC exclusion"),
)


PROFILES: dict[str, ObservationProfile] = {
  "secoc-verification-state": ObservationProfile(
    "secoc-verification-state",
    ("MAC verification result byte plus current and pending synchronization " +
     "trip/reset words: dynamic discriminators for SecOC Gate-2 acceptance and " +
     "the post-reset replay window without any write primitive. The " +
     "command-5 generated-result buffer and ICU-S driver polling word are " +
     "firmware-excluded from XCP and deliberately absent"),
    (0xFEBE555C, 0xFEBE5568, 0xFEBE556C, 0xFEBE5560, 0xFEBE5562, 0xFEBE5564),
    ("SECOC-011", "SECOC-012", "SECOC-029"),
  ),
  "actuation-discriminator": ObservationProfile(
    "actuation-discriminator",
    "d/q-reference words plus the three staged TSG3 comparison bytes",
    (0xFEBE6D28, 0xFEBE6D29, 0xFEBE6D2A, 0xFEBE6D2B, 0xFEBE38A2, 0xFEBE38A4, 0xFEBE38A6),
    ("COM-007",),
  ),
  "diagnostic-control-state": ObservationProfile(
    "diagnostic-control-state",
    "volatile state associated with WDBI 2012/2013/2014 lifecycle/control findings",
    (0xFEBEB18F, 0xFEBEB18E, 0xFEBEB434, 0xFEBEB435, 0xFEBEB3EE, 0xFEBEB3EC, 0xFEBEB3E7),
    ("DIAG-APP-016", "DIAG-APP-017", "DIAG-APP-018"),
  ),
  "routine-lifecycle-state": ObservationProfile(
    "routine-lifecycle-state",
    "one-shot/state-gated RoutineControl lifecycle flags and group states",
    (0xFEBE8157, 0xFEBE8158, 0xFEBE8159, 0xFEBEB454, 0xFEBEB455, 0xFEBEB456, 0xFEBEB2D5),
    ("DIAG-APP-010", "DIAG-APP-011"),
  ),
  "async-ba-state": ObservationProfile(
    "async-ba-state",
    "shared async-operation queue plus persistent BA authorization marker/countdown",
    (0xFEBE828C, 0xFEBE8290, 0xFEBE8291, 0xFEBE8292, 0xFEBE8293, 0xFEBE5F27, 0xFEBE5F28),
    ("DIAG-APP-023", "SEC-APP-007"),
  ),
  "ba-operational-state": ObservationProfile(
    "ba-operational-state",
    "SID-BA lifecycle/alternate-speed/inhibit state without invoking any BA operation",
    (0xFEBEB112, 0xFEBEB113, 0xFEBEB116, 0xFEBEB117, 0xFEBEB118, 0xFEBEE894, 0xFEBEE895),
    ("DIAG-APP-024",),
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


def assert_no_write_commands(requests: Iterable[tuple[str, bytes]]) -> None:
  """Fail closed if a supposedly read-only plan contains a source-memory mutation."""
  for operation, request in requests:
    if len(request) != FRAME_SIZE:
      raise XcpObserverError(f"{operation} request must be exactly eight bytes")
    opcode = request[0]
    if opcode in FORBIDDEN_COMMANDS:
      raise XcpObserverError(
        f"{operation} uses forbidden opcode 0x{opcode:02X}: {FORBIDDEN_COMMANDS[opcode]}"
      )


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
  planned = tuple(requests)
  assert_no_write_commands(planned)
  assert_no_write_commands((("stop_daq_list", start_stop_daq_list_request(False)),))
  return planned


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


def _exchange(panda, *, bus: int, request: bytes, timeout: float, operation: str,
              timings: list[dict] | None = None) -> bytes:
  assert_no_write_commands(((operation, request),))
  if timeout <= 0:
    raise XcpObserverError("XCP response timeout must be positive")
  panda.can_recv()
  requested_monotonic = time.monotonic()
  panda.can_send(REQUEST_ID, request, bus)
  response = _recv_control(panda, bus=bus, timeout=timeout, operation=operation)
  received_monotonic = time.monotonic()
  if timings is not None:
    timings.append({
      "operation": operation,
      "request_hex": request.hex(),
      "requested_monotonic": requested_monotonic,
      "received_monotonic": received_monotonic,
      "rtt_seconds": received_monotonic - requested_monotonic,
      "received_wall_utc": datetime.now(UTC).isoformat(timespec="milliseconds"),
    })
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


def configure_daq(panda, *, bus: int, addresses: Iterable[int], timeout: float) -> list[dict]:
  timings: list[dict] = []
  start_sent = False
  try:
    for operation, request in configuration_requests(addresses):
      if operation == "start_daq_list":
        start_sent = True
      response = _exchange(
        panda, bus=bus, request=request, timeout=timeout, operation=operation, timings=timings,
      )
      if operation == "start_daq_list" and response[1] != 0:
        raise XcpObserverError(f"START_DAQ_LIST first PID is 0x{response[1]:02X}, expected 0")
  except Exception:
    if start_sent:
      try:
        stop_daq(panda, bus=bus, timeout=timeout, timings=timings)
      except Exception:
        pass
    raise
  return timings


def stop_daq(panda, *, bus: int, timeout: float, timings: list[dict] | None = None) -> None:
  _exchange(
    panda, bus=bus, request=start_stop_daq_list_request(False), timeout=timeout,
    operation="stop_daq_list", timings=timings,
  )


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


def _latency_statistics(seconds: list[float]) -> dict | None:
  if not seconds:
    return None
  ordered = sorted(seconds)
  return {
    "count": len(seconds),
    "min_seconds": min(seconds),
    "max_seconds": max(seconds),
    "mean_seconds": sum(seconds) / len(seconds),
    "median_seconds": ordered[len(ordered) // 2],
    "jitter_seconds": max(seconds) - min(seconds),
    "samples_source": "time.monotonic deltas only",
  }


def control_rtt_statistics(timings: list[dict]) -> dict | None:
  return _latency_statistics([float(row["rtt_seconds"]) for row in timings])


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
      captured_monotonic = time.monotonic()
      decoded["t_ms"] = round((captured_monotonic - started) * 1000.0, 3)
      decoded["captured_monotonic"] = captured_monotonic
      decoded["captured_wall_utc"] = datetime.now(UTC).isoformat(timespec="milliseconds")
      captured.append(decoded)
      if len(captured) >= max_frames:
        break
    time.sleep(0.001)
  return captured


def probe_xcp(profile: str = "actuation-discriminator", progress_cb=None,
              capture_seconds: float = 1.5, max_frames: int = 512) -> dict:
  """Measure XCP reachability plus bounded F4/volatile-DAQ observations."""
  if not is_agnos():
    raise NotAGNOSError
  if profile not in PROFILES:
    raise XcpObserverError(f"unknown XCP profile: {profile}")
  cb = progress_cb or _noop

  subprocess.run(["pkill", "-9", "-f", "manager.py"], check=False)
  subprocess.run(["pkill", "-9", "-f", "pandad"], check=False)
  time.sleep(2)

  result = {
    "schema": SCHEMA,
    "status": "failed", "panda": "", "eps_bus": -1, "f181": "", "f181_hex": "",
    "profile": profile, "profile_description": PROFILES[profile].description,
    "profile_finding_ids": list(PROFILES[profile].finding_ids),
    "xcp_request_id": f"0x{REQUEST_ID:03x}", "xcp_response_id": f"0x{RESPONSE_ID:03x}",
    "connect_response": "", "snapshot": [], "frames": [], "message": "",
    "profile_semantics_verified": False, "volatile_daq_configuration": True,
    "source_memory_writes_implemented": False, "write_commands_implemented": False,
    "forbidden_command_opcodes": {f"0x{opcode:02X}": reason for opcode, reason in sorted(FORBIDDEN_COMMANDS.items())},
    "wall_clock_rate_claimed": False, "control_timing": {"requests": [], "rtt_statistics": None},
    "capture_window": {},
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

  exact_semantics = EXACT_APPLICATION_ID in identity
  result["profile_semantics_verified"] = exact_semantics
  result["profile_semantics"] = (
    "firmware-verified for exact 8965B4512000" if exact_semantics else
    "8965B4512000-derived candidate addresses; raw values only on this F181"
  )

  addresses = PROFILES[profile].addresses
  readable_addresses: list[int] = []
  cb(step="snapshot", last="bounded F4 LocalRAM reads")
  for address in addresses:
    row = {"address": f"0x{address:08x}"}
    try:
      value = short_upload(panda, bus=bus, address=address, length=1, timeout=0.35)
      row.update(ok=True, value=value[0])
      readable_addresses.append(address)
    except XcpObserverError as e:
      row.update(ok=False, error=str(e))
    result["snapshot"].append(row)

  # DAQ configuration mutates only the volatile XCP measurement table. Configure only
  # addresses that already answered F4 on this target, and always send STOP after a
  # successful start. This is intentionally allowed cross-calibration because failure
  # merely rejects the observation; it does not modify source memory or persistent state.
  if readable_addresses:
    cb(step="daq", last=f"configure {profile}")
    configured = False
    control_timings: list[dict] = []
    try:
      control_timings = configure_daq(panda, bus=bus, addresses=readable_addresses, timeout=0.35)
      configured = True
      cb(step="capture", last="capture 0x7F8 DAQ DTOs")
      capture_started_monotonic = time.monotonic()
      capture_started_wall = datetime.now(UTC).isoformat(timespec="milliseconds")
      result["frames"] = capture_dto(
        panda, bus=bus, addresses=readable_addresses, duration=capture_seconds, max_frames=max_frames,
      )
      result["capture_window"] = {
        "started_monotonic": capture_started_monotonic,
        "finished_monotonic": time.monotonic(),
        "started_wall_utc": capture_started_wall,
        "finished_wall_utc": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "requested_duration_seconds": capture_seconds,
        "requested_max_frames": max_frames,
        "truncated_by_frame_cap": len(result["frames"]) >= max_frames,
        "clocks": "monotonic deltas only for intervals; UTC for cross-log correlation",
      }
    except XcpObserverError as e:
      result["daq_error"] = str(e)
    finally:
      if configured:
        try:
          stop_daq(panda, bus=bus, timeout=0.35, timings=control_timings)
        except Exception as e:
          result["cleanup_error"] = f"{type(e).__name__}: {e}"
      result["control_timing"] = {
        "requests": control_timings,
        "rtt_statistics": control_rtt_statistics(control_timings),
      }

  result["status"] = "observed" if readable_addresses else "reachable"
  semantic_note = (
    "Profile semantics are firmware-verified for this exact calibration." if exact_semantics else
    "Profile addresses came from 8965B4512000; on this F181 they are raw observation candidates only."
  )
  result["message"] = " ".join((
    f"XCP CONNECT succeeded; {len(readable_addresses)}/{len(addresses)} bounded F4 candidate read(s) returned data",
    f"and {len(result['frames'])} volatile DAQ DTO frame(s) were captured.", semantic_note,
    "No XCP source-memory write command was implemented.",
  ))
  return result
