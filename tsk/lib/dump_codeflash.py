#!/usr/bin/env python3
"""Exact-target 2026 Camry/F33 EPS CodeFlash acquisition.

The resulting memory acquisition is read-only CodeFlash, but the transport enters
PROGRAMMING and executes an authenticated 4 KiB RAM range-reader.  For that reason
this module is deliberately exact-target gated to the field-verified
8965F3307000 / 8A3113303100 specimen and refuses before PROGRAMMING if identity,
route, payload hash, bootstrap evidence, or NRTD state does not match.
"""
from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from tsk.lib.bootstrap_profile import (
  BOOT_SA_SECRET, BootstrapProfileError, require_evidenced_fixture,
)
from tsk.lib.camry_f33 import (
  CAMRY_F33_APP_F181, CAMRY_F33_BOOT_F181, CAMRY_F33_CODEFLASH, CAMRY_F33_READY, CAMRY_F33_ROUTE,
)
from tsk.lib.diagnostic_route import AmbiguousDiagnosticRouteError, discover_eps_route_with_routing, route_fields
from tsk.lib.env import CODEFLASH_DIR, CODEFLASH_PAYLOAD_PATH, is_agnos
from tsk.lib.extractor import NotAGNOSError, RetryError, TSKExtractor
from tsk.lib.programming import ProgrammingHandoffError, enter_programming_bootloader, uds_client
from tsk.lib.ram_exec_geometry import (
  COMMITTED_PAYLOAD_CONTRACT, RamExecGeometryError, build_request_download_data,
  build_verify_routine_data, resolve_ram_exec_geometry, transfer_chunks,
)


DUMP_START = int(CAMRY_F33_CODEFLASH["raw_transport_start"])
DUMP_END = int(CAMRY_F33_CODEFLASH["raw_transport_end"])
DUMP_TOTAL = DUMP_END - DUMP_START
WORD_SIZE = 4
EXPECTED_WORDS = DUMP_TOTAL // WORD_SIZE
NORMALIZED_SIZE = int(CAMRY_F33_CODEFLASH["normalized_size"])
EXPECTED_RAW_SHA256 = str(CAMRY_F33_CODEFLASH["raw_transport_sha256"])
EXPECTED_NORMALIZED_SHA256 = str(CAMRY_F33_CODEFLASH["normalized_sha256"])
PAYLOAD_SHA256 = str(CAMRY_F33_CODEFLASH["payload_sha256"])
PAYLOAD_SIZE = int(CAMRY_F33_CODEFLASH["payload_size"])
TRIGGER_ADDR = 0x000E0000
TRIGGER_SIZE = 0x00008000
IDLE_TIMEOUT = 10.0
MAX_SECONDS = 1200.0
MAX_CONSECUTIVE_SPI_ERRORS = 100
RESPONSE_PENDING = bytes.fromhex("037f317800000000")


def _noop(**kwargs) -> None:
  pass


def _sha256(data: bytes) -> str:
  return hashlib.sha256(data).hexdigest()


def _utc_now() -> str:
  return datetime.now(UTC).isoformat(timespec="milliseconds")


def _exact_route(route: dict) -> bool:
  return all(int(route.get(key, -1)) == int(CAMRY_F33_ROUTE[key]) for key in ("tx", "rx", "tx_bus", "rx_bus", "elm327_param"))


def _decode_dump_frame(addr: int, data: bytes, bus: int) -> tuple[int, bytes] | None:
  """Decode one Calvin range-reader response into (word_index, four bytes)."""
  if int(bus) != int(CAMRY_F33_ROUTE["rx_bus"]) or int(addr) != int(CAMRY_F33_ROUTE["rx"]) or len(data) < 8:
    return None
  data = bytes(data)
  if data == RESPONSE_PENDING:
    return None
  header = struct.unpack("<I", data[:4])[0]
  if (header & 0xFF) != 0x07:
    return None
  address = (header >> 8) & 0xFFFFFF
  if address < DUMP_START or address + WORD_SIZE > DUMP_END or address & (WORD_SIZE - 1):
    return None
  return (address - DUMP_START) // WORD_SIZE, data[4:8]


def _load_resume(dump_file: Path | None, coverage_file: Path | None) -> tuple[bytearray, bytearray]:
  image = bytearray(DUMP_TOTAL)
  seen = bytearray(EXPECTED_WORDS)
  if dump_file is None and coverage_file is None:
    return image, seen
  if dump_file is None or coverage_file is None:
    raise RetryError("CodeFlash resume requires both dump and coverage paths")
  raw = dump_file.read_bytes()
  coverage = coverage_file.read_bytes()
  if len(raw) != DUMP_TOTAL or len(coverage) != EXPECTED_WORDS:
    raise RetryError("CodeFlash resume artifact has the wrong size")
  if any(value not in (0, 1) for value in coverage):
    raise RetryError("CodeFlash resume coverage contains values other than 0/1")
  image[:] = raw
  seen[:] = coverage
  return image, seen


def _integrity(image: bytes, seen: bytes) -> dict:
  complete = len(seen) == EXPECTED_WORDS and all(seen)
  raw_sha = _sha256(image) if complete else None
  normalized = image[:NORMALIZED_SIZE] if complete else b""
  normalized_sha = _sha256(normalized) if complete else None
  upper_erased = bool(complete and all(value == 0xFF for value in image[NORMALIZED_SIZE:]))
  return {
    "complete": complete,
    "raw_sha256": raw_sha,
    "raw_sha256_matches_retained": raw_sha == EXPECTED_RAW_SHA256 if raw_sha else False,
    "normalized_sha256": normalized_sha,
    "normalized_sha256_matches_retained": normalized_sha == EXPECTED_NORMALIZED_SHA256 if normalized_sha else False,
    "upper_half_all_ff": upper_erased,
  }


def _artifact_paths(output_dir: Path, stamp: str) -> tuple[Path, Path, Path, Path]:
  base = output_dir / f"camry_8965F3307000_codeflash_{stamp}"
  return base.with_suffix(".bin"), base.with_suffix(".coverage.bin"), base.with_suffix(".run.json"), base.with_suffix(".normalized.bin")


def dump(progress_cb=None, *, output_dir: Path | None = None,
         resume_dump: Path | None = None, resume_coverage: Path | None = None) -> dict:
  """Acquire the exact F3307000 0..2 MiB CodeFlash transport range.

  The successful retained field run proved the exact payload/bootstrap tuple used
  here.  No F181 prefix/family fallback exists.  A partial result is always
  persisted with one-byte-per-word coverage and can be supplied on a later call
  through ``resume_dump`` + ``resume_coverage``; overlapping words must agree.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop
  out = Path(output_dir or CODEFLASH_DIR)
  out.mkdir(parents=True, exist_ok=True)
  stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
  dump_path, coverage_path, run_path, normalized_path = _artifact_paths(out, stamp)

  payload = Path(CODEFLASH_PAYLOAD_PATH).read_bytes()
  if len(payload) != PAYLOAD_SIZE or _sha256(payload) != PAYLOAD_SHA256:
    raise RetryError("Camry CodeFlash payload hash/size mismatch")
  try:
    fixture_evidence = require_evidenced_fixture(CAMRY_F33_APP_F181, PAYLOAD_SHA256)
  except BootstrapProfileError as e:
    raise RetryError("Camry CodeFlash payload is not exact-F181 evidenced: " + str(e)) from e

  image, seen = _load_resume(resume_dump, resume_coverage)
  initial_words = sum(seen)
  report: dict = {
    "schema": "tsk-camry-f33-codeflash-v1",
    "started_at": _utc_now(),
    "target": {
      "application_f181_hex": CAMRY_F33_APP_F181.hex(),
      "boot_f181_hex": CAMRY_F33_BOOT_F181.hex(),
      "route": route_fields(CAMRY_F33_ROUTE),
    },
    "payload": {"path": str(CODEFLASH_PAYLOAD_PATH), "sha256": PAYLOAD_SHA256, "size": len(payload)},
    "resume": {"initial_words": initial_words, "dump": str(resume_dump or ""), "coverage": str(resume_coverage or "")},
    "stages": [],
    "result": {},
  }

  def save() -> None:
    run_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

  def stage(name: str, status: str, **detail) -> None:
    report["stages"].append({"at": _utc_now(), "name": name, "status": status, **detail})
    save()

  save()
  cb(status="running", words_done=initial_words, words_total=EXPECTED_WORDS, message="")

  from Crypto.Cipher import AES
  from opendbc.car.isotp import isotp_send
  from opendbc.car.structs import CarParams
  from opendbc.car.uds import ACCESS_TYPE, ROUTINE_CONTROL_TYPE, SERVICE_TYPE, SESSION_TYPE, \
    InvalidServiceIdError, MessageTimeoutError, NegativeResponseError
  from panda.python.spi import PandaSpiException

  # Mirror the existing TSK exclusive-Panda operations.  Manager will be restarted
  # by the normal device lifecycle after this one-shot tool exits.
  subprocess.run(["pkill", "-9", "-f", "manager.py"], check=False)
  subprocess.run(["pkill", "-9", "-f", "pandad"], check=False)
  time.sleep(2)

  panda = TSKExtractor._connect_panda()
  handoff: dict = {}
  route: dict | None = None
  try:
    try:
      route = discover_eps_route_with_routing(
        panda, [1], preferred_tx=int(CAMRY_F33_ROUTE["tx"]), addresses=[int(CAMRY_F33_ROUTE["tx"])],
        preferred_timeout=0.4, scan_timeout=0.1,
      )
    except AmbiguousDiagnosticRouteError as e:
      raise RetryError(f"Ambiguous Camry EPS route: {e}") from e
    if route is None or not _exact_route(route):
      raise RetryError(f"Refusing CodeFlash payload: exact Camry route not present ({route_fields(route) if route else 'none'})")

    panda.set_safety_mode(CarParams.SafetyModel.elm327, int(CAMRY_F33_ROUTE["elm327_param"]))
    app = uds_client(panda, route, timeout=0.5, response_pending_timeout=3.0)
    try:
      app.diagnostic_session_control(SESSION_TYPE.DEFAULT)
    except Exception:
      pass
    app_f181 = bytes(app.read_data_by_identifier(0xF181))
    if app_f181 != CAMRY_F33_APP_F181:
      raise RetryError(f"Refusing CodeFlash payload: unexpected application F181 {app_f181.hex()}")
    stage("application identity", "accepted", observed_hex=app_f181.hex())

    try:
      geometry = resolve_ram_exec_geometry(app_f181)
      COMMITTED_PAYLOAD_CONTRACT.validate_geometry(geometry)
    except RamExecGeometryError as e:
      raise RetryError("Refusing CodeFlash payload: RAM-exec geometry mismatch: " + str(e)) from e

    # Independent NRTD gate using the same exact wire bit validated by the
    # controlled NRTD->READY field capture.
    ready_samples: list[int] = []
    deadline = time.monotonic() + 2.5
    while time.monotonic() < deadline:
      for frame in panda.can_recv():
        if len(frame) == 3:
          addr, data, bus = frame
        else:
          addr, *_, data, bus = frame
        if int(bus) == int(CAMRY_F33_ROUTE["rx_bus"]) and int(addr) == int(CAMRY_F33_READY["address"]) and len(data) == 8:
          ready_samples.append((bytes(data)[int(CAMRY_F33_READY["byte"])] >> int(CAMRY_F33_READY["bit"])) & 1)
      if ready_samples:
        break
      time.sleep(0.001)
    if not ready_samples:
      raise RetryError("Refusing CodeFlash payload: no bus-1 0x51E Ready sample")
    if any(ready_samples):
      raise RetryError("Refusing CodeFlash payload: vehicle is READY; use Not Ready to Drive")
    stage("NRTD Ready-status guard", "accepted", ready_values=[0])

    try:
      boot_route, handoff = enter_programming_bootloader(
        panda, route, prepare_sessions=True, settle_extended=0.7, reappearance_timeout=8.0,
      )
    except ProgrammingHandoffError as e:
      detail = f" ({e.telemetry})" if e.telemetry else ""
      raise RetryError("Can't enter exact Camry programming bootloader" + detail) from e
    if not _exact_route(boot_route):
      raise RetryError(f"Camry bootloader route changed unexpectedly: {route_fields(boot_route)}")
    stage("programming handoff", "accepted", handoff=handoff)

    boot = uds_client(panda, boot_route, timeout=0.5, response_pending_timeout=3.0)
    boot_f181 = bytes(boot.read_data_by_identifier(0xF181))
    if boot_f181 != CAMRY_F33_BOOT_F181:
      raise RetryError(f"Unexpected Camry bootloader F181 {boot_f181.hex()}")
    stage("boot identity", "accepted", observed_hex=boot_f181.hex())

    boot = uds_client(panda, boot_route, timeout=0.5, response_pending_timeout=3.0)
    try:
      boot.diagnostic_session_control(SESSION_TYPE.DEFAULT)
      boot.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
      boot.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
      seed_record = bytes(16)
      seed = bytes(boot.security_access(ACCESS_TYPE.REQUEST_SEED, data_record=seed_record))
      if len(seed) != 16:
        raise RetryError(f"Unexpected boot SecurityAccess seed length {len(seed)}")
      derived = AES.new(BOOT_SA_SECRET, AES.MODE_ECB).decrypt(seed_record)
      key = AES.new(derived, AES.MODE_ECB).encrypt(seed)
      boot.security_access(ACCESS_TYPE.SEND_KEY, key)
      stage("boot SecurityAccess", "accepted")

      # Exact F3307000 field evidence proves the old-stack zero selector / 45 00 grammar.
      boot.write_data_by_identifier(0x203, bytes(5))
      boot.write_data_by_identifier(0x201, bytes(16))
      boot.write_data_by_identifier(0x202, bytes(16))
      stage("old-stack DID 0203/0201/0202", "accepted")

      request = build_request_download_data(geometry)
      boot._uds_request(SERVICE_TYPE.REQUEST_DOWNLOAD, data=request)
      for i, chunk in enumerate(transfer_chunks(payload, geometry), start=1):
        boot.transfer_data(i, chunk)
      boot.request_transfer_exit()
      verify = build_verify_routine_data(geometry)
      boot.routine_control(ROUTINE_CONTROL_TYPE.START, 0x10F0, verify)
      stage("authenticated payload", "accepted", request_download=request.hex(), verify=verify.hex())
    except RetryError:
      raise
    except (InvalidServiceIdError, MessageTimeoutError, NegativeResponseError) as e:
      raise RetryError(f"Camry CodeFlash bootstrap failed: {type(e).__name__}") from e

    trigger = b"\x31\x01\xff\x00\x45\x00" + struct.pack("!I", TRIGGER_ADDR) + struct.pack("!I", TRIGGER_SIZE)
    panda.can_clear(0xFFFF)
    time.sleep(0.01)
    isotp_send(panda, trigger, int(CAMRY_F33_ROUTE["tx"]), bus=int(CAMRY_F33_ROUTE["tx_bus"]))
    stage("CodeFlash callback trigger", "sent", data_hex=trigger.hex())

    unique_words = initial_words
    duplicate_words = 0
    conflicts = 0
    raw_rx_frames = 0
    spi_errors = 0
    consecutive_spi_errors = 0
    started = time.monotonic()
    last_progress = started

    while unique_words < EXPECTED_WORDS and time.monotonic() - started <= MAX_SECONDS:
      made_progress = False
      try:
        frames = panda.can_recv()
        consecutive_spi_errors = 0
      except PandaSpiException:
        spi_errors += 1
        consecutive_spi_errors += 1
        if consecutive_spi_errors >= MAX_CONSECUTIVE_SPI_ERRORS:
          break
        continue

      for frame in frames:
        if len(frame) == 3:
          addr, data, bus = frame
        else:
          addr, *_, data, bus = frame
        decoded = _decode_dump_frame(addr, bytes(data), bus)
        if decoded is None:
          continue
        raw_rx_frames += 1
        index, word = decoded
        offset = index * WORD_SIZE
        if seen[index]:
          duplicate_words += 1
          if image[offset:offset + WORD_SIZE] != word:
            conflicts += 1
            raise RetryError(f"Conflicting CodeFlash word at 0x{DUMP_START + offset:08x}")
          continue
        image[offset:offset + WORD_SIZE] = word
        seen[index] = 1
        unique_words += 1
        made_progress = True

      if made_progress:
        last_progress = time.monotonic()
        if unique_words % 4096 == 0:
          cb(status="running", words_done=unique_words, words_total=EXPECTED_WORDS, message="")
      elif time.monotonic() - last_progress > IDLE_TIMEOUT:
        break
      else:
        time.sleep(0.001)

    elapsed = time.monotonic() - started
    dump_path.write_bytes(bytes(image))
    coverage_path.write_bytes(bytes(seen))
    integrity = _integrity(bytes(image), bytes(seen))
    if integrity["complete"]:
      normalized_path.write_bytes(bytes(image[:NORMALIZED_SIZE]))

    status = "complete" if integrity["complete"] and conflicts == 0 else ("partial" if unique_words else "empty")
    report["result"] = {
      "status": status,
      "dump_path": str(dump_path),
      "coverage_path": str(coverage_path),
      "normalized_path": str(normalized_path) if integrity["complete"] else "",
      "expected_words": EXPECTED_WORDS,
      "unique_words": unique_words,
      "initial_words": initial_words,
      "duplicate_words": duplicate_words,
      "conflicts": conflicts,
      "raw_rx_frames": raw_rx_frames,
      "spi_errors": spi_errors,
      "elapsed_s": round(elapsed, 3),
      "coverage_percent": round(unique_words * 100.0 / EXPECTED_WORDS, 6),
      "integrity": integrity,
      "route": route_fields(boot_route),
      "application_f181": app_f181.hex(),
      "bootstrap_evidence": fixture_evidence.public_dict(),
      "programming_handoff": handoff,
    }
    report["finished_at"] = _utc_now()
    stage("CodeFlash stream", status, unique_words=unique_words, expected_words=EXPECTED_WORDS,
          conflicts=conflicts, spi_errors=spi_errors)
    cb(status=status, words_done=unique_words, words_total=EXPECTED_WORDS,
       message="CodeFlash dump complete." if status == "complete" else "Partial CodeFlash dump retained with coverage bitmap.")
    return report["result"]
  finally:
    TSKExtractor._close_panda()
