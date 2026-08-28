#!/usr/bin/env python3
"""Scan and clear test-induced DTCs on the relay-correct 2026 Camry.

Exact live-validated route:
  * physical UDS 0x14 FF FF FF for ECUs that support ClearDiagnosticInformation
  * functional legislated OBD Mode 04 on 0x7DF for Engine/MG/Hybrid/HV Battery/Brake
  * final DTC status sweep; nonzero fault-status bits make the command fail

pandad must be stopped so this process owns the Panda exclusively.
"""

import argparse
import sys
import time
from subprocess import CalledProcessError, check_output

from opendbc.car.structs import CarParams
from opendbc.car.uds import (
  DATA_IDENTIFIER_TYPE,
  DTC_GROUP_TYPE,
  DTC_REPORT_TYPE,
  DTC_STATUS_MASK_TYPE,
  MessageTimeoutError,
  NegativeResponseError,
  UdsClient,
  get_dtc_num_as_str,
  get_dtc_status_names,
)
from panda import Panda

BUS = 0
EXPECTED_EPS_F181 = b"8965F3307000"
FAULT_STATUS_MASK = 0xAF  # failed/current, pending, confirmed, failed-since-clear, warning requested

# Exact post-repin diagnostic sweep used to validate the 2026 Camry clear procedure.
ECUS = {
  0x700: "Engine",
  0x701: "ECT",
  0x724: "Motor Generator",
  0x7D2: "Hybrid Control",
  0x747: "HV Battery",
  0x745: "Plug-in Control",
  0x707: "ECU 0x707",
  0x703: "ECU 0x703",
  0x7A1: "Power Steering",
  0x7B0: "Brake/EPB",
  0x750: "ECU 0x750",
  0x7B3: "ECU 0x7B3",
  0x7C4: "Air Conditioner",
  0x7D1: "ECU 0x7D1",
  0x7D0: "ECU 0x7D0",
  0x792: "Front Recognition Camera",
  0x7A2: "ECU 0x7A2",
}

LEGISLATED_RESPONDERS = {0x7E8, 0x7EA, 0x7EB, 0x7ED, 0x7EE}


def require_exclusive_panda() -> None:
  try:
    check_output(["pidof", "pandad"])
  except CalledProcessError as e:
    if e.returncode == 1:
      return
    raise
  raise SystemExit("pandad is running; stop openpilot/manager before using this script")


def uds(panda: Panda, addr: int) -> UdsClient:
  return UdsClient(panda, addr, bus=BUS, timeout=0.35, response_pending_timeout=2.0)


def parse_dtc_response(data: bytes) -> list[tuple[str, int]]:
  if not data:
    return []
  payload = data[1:]  # first byte is status-availability mask
  if len(payload) % 4:
    raise ValueError(f"malformed DTC response length {len(data)}")
  return [(get_dtc_num_as_str(payload[i:i + 3]), payload[i + 3]) for i in range(0, len(payload), 4)]


def read_ecu_dtcs(panda: Panda, addr: int) -> list[tuple[str, int]] | None:
  try:
    data = uds(panda, addr).read_dtc_information(DTC_REPORT_TYPE.DTC_BY_STATUS_MASK, DTC_STATUS_MASK_TYPE.ALL)
    return parse_dtc_response(data)
  except (MessageTimeoutError, NegativeResponseError):
    return None


def scan(panda: Panda, *, show_all: bool = False) -> tuple[dict[int, list[tuple[str, int]]], list[tuple[int, str, int]]]:
  responding: dict[int, list[tuple[str, int]]] = {}
  faults: list[tuple[int, str, int]] = []
  for addr, name in ECUS.items():
    records = read_ecu_dtcs(panda, addr)
    if records is None:
      if show_all:
        print(f"{addr:#05x} {name}: no response")
      continue
    responding[addr] = records
    active = [(dtc, status) for dtc, status in records if status & FAULT_STATUS_MASK]
    faults.extend((addr, dtc, status) for dtc, status in active)
    if show_all or active:
      print(f"{addr:#05x} {name}: {len(records)} DTC record(s), {len(active)} fault-status record(s)")
      for dtc, status in active:
        print(f"  {dtc} status={status:#04x} {' '.join(get_dtc_status_names(status))}")
  return responding, faults


def verify_vehicle_identity(panda: Panda) -> None:
  try:
    f181 = uds(panda, 0x7A1).read_data_by_identifier(DATA_IDENTIFIER_TYPE.APPLICATION_SOFTWARE_IDENTIFICATION)
  except Exception as e:
    raise SystemExit(f"refusing to clear: could not verify EPS F181 at 0x7A1: {e}") from e
  if EXPECTED_EPS_F181 not in f181:
    raise SystemExit(f"refusing to clear: EPS F181 does not contain {EXPECTED_EPS_F181.decode()!r}: {f181!r}")
  print(f"vehicle guard: EPS F181 contains {EXPECTED_EPS_F181.decode()}")


def clear_physical_uds(panda: Panda, responders: dict[int, list[tuple[str, int]]]) -> None:
  print("\nphysical UDS clear (14 FF FF FF):")
  for addr in responders:
    try:
      uds(panda, addr).clear_diagnostic_information(DTC_GROUP_TYPE.ALL)
      print(f"  {addr:#05x} {ECUS[addr]}: cleared")
    except NegativeResponseError as e:
      print(f"  {addr:#05x} {ECUS[addr]}: not supported ({e})")
    except MessageTimeoutError:
      print(f"  {addr:#05x} {ECUS[addr]}: timeout")


def functional_obd_mode04(panda: Panda) -> set[int]:
  # Exact live-validated standard CAN frame: functional request 0x7DF, one-byte Mode 04 payload.
  panda.can_clear(0xFFFF)
  panda.can_send(0x7DF, bytes.fromhex("0104000000000000"), BUS)

  positive: set[int] = set()
  deadline = time.monotonic() + 1.0
  while time.monotonic() < deadline:
    for addr, data, bus in panda.can_recv():
      if bus == BUS and addr in LEGISLATED_RESPONDERS and len(data) >= 2 and data[0:2] == b"\x01\x44":
        positive.add(addr)
    if positive == LEGISLATED_RESPONDERS:
      break

  print("\nfunctional OBD Mode 04 (0x7DF):")
  for addr in sorted(LEGISLATED_RESPONDERS):
    print(f"  {addr:#05x}: {'positive 0x44' if addr in positive else 'NO POSITIVE RESPONSE'}")
  return positive


def main() -> int:
  parser = argparse.ArgumentParser(description="2026 Camry exact-vehicle DTC scan/clear utility")
  parser.add_argument("action", choices=("scan", "clear"), help="scan only, or scan -> clear -> verify")
  args = parser.parse_args()

  require_exclusive_panda()
  panda = Panda()
  panda.set_safety_mode(CarParams.SafetyModel.elm327, 0)

  verify_vehicle_identity(panda)
  print("\npre-clear scan:" if args.action == "clear" else "\nDTC scan:")
  responders, faults = scan(panda, show_all=args.action == "scan")
  print(f"responding ECUs: {len(responders)}; fault-status records: {len(faults)}")

  if args.action == "scan":
    return 1 if faults else 0

  clear_physical_uds(panda, responders)
  positives = functional_obd_mode04(panda)
  if positives != LEGISLATED_RESPONDERS:
    print("warning: not all live-validated legislated responders acknowledged Mode 04")

  time.sleep(0.2)
  print("\npost-clear verification:")
  final_responders, final_faults = scan(panda, show_all=False)
  print(f"responding ECUs: {len(final_responders)}; remaining fault-status records: {len(final_faults)}")
  if final_faults:
    print("FAILED: fault-status DTCs remain")
    return 2

  print("PASS: all responding ECUs are clear of fault-status DTCs")
  return 0


if __name__ == "__main__":
  sys.exit(main())
