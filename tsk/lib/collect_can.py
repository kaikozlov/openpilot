#!/usr/bin/env python3
"""Collect full-payload CAN evidence and annotate the prior SecOC oracle IDs.

Vehicle requirement: READY Mode (hybrid system on) so authenticated traffic is active.
Every non-echo frame on every observed bus is appended to ``can_oracle.ndjson``. Known
Sienna/Corolla sync and protected IDs are annotations and matcher inputs, never capture
filters.

Shares the panda-takeover preamble with dump_dataflash.py / extractor.py by
deliberate duplication: this is a distinct operation — a read-only bus capture with
no UDS session — kept independently testable rather than coupled through a helper.
"""
import json
import os
import subprocess
import time
from datetime import datetime, UTC
from pathlib import Path
from uuid import uuid4

from tsk.lib.env import CAN_ORACLE_PATH, is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor

SYNC_ADDR = 0x0F
PROTECTED_ADDRS = {0x131, 0x2E4, 0x344}
# Prior Sienna/Corolla IDs are annotations used by the existing matcher. Capture itself
# is unfiltered across all buses and arbitration IDs.

# UI/ready thresholds (raw frame counts, matching the index row's "N/50", "N/30").
SYNC_TARGET = 50
PROTECTED_TARGET = 30
COLLECT_SECONDS = 60.0  # hard cap; collection stops early once both targets are met


def oracle_path() -> Path:
  return Path(CAN_ORACLE_PATH)


def _noop(**kwargs) -> None:
  pass


def count_oracle_frames(path=None) -> tuple:
  """Count (sync_frames, protected_frames) in a persisted oracle; (0, 0) if missing.

  Skips malformed lines, matching the matcher's loader, so a torn capture is counted
  legibly rather than raising.
  """
  p = Path(path) if path is not None else oracle_path()
  sync = 0
  protected = 0
  try:
    with p.open("r", encoding="utf-8") as f:
      for line in f:
        if not line.strip():
          continue
        try:
          r = json.loads(line)
          addr = int(r["addr"])
        except (ValueError, KeyError, TypeError):
          continue
        if addr == SYNC_ADDR:
          sync += 1
        elif addr in PROTECTED_ADDRS:
          protected += 1
  except OSError:
    return 0, 0
  return sync, protected


def collect(progress_cb=None, seconds=COLLECT_SECONDS) -> dict:
  """Capture SecOC oracle frames for up to `seconds` and write can_oracle.ndjson.

  progress_cb, if given, is called as progress_cb(seconds=, sync=, protected=).
  Returns {status, sync, protected, oracle_path, message} where status is one of:
    complete | insufficient | failed. Raises NotAGNOSError off-device.
  """
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop

  from opendbc.car.structs import CarParams

  # Kill the manager so pandad doesn't fight for the panda (mirrors dump()).
  subprocess.run(["pkill", "-9", "-f", "manager.py"], check=False)
  subprocess.run(["pkill", "-9", "-f", "pandad"], check=False)
  time.sleep(2)

  panda = TSKExtractor._connect_panda()
  panda.set_safety_mode(CarParams.SafetyModel.elm327)

  path = oracle_path()
  path.parent.mkdir(parents=True, exist_ok=True)

  sync_count = 0
  protected_count = 0
  begin = time.monotonic()
  last_progress = begin
  cb(seconds=0.0, sync=0, protected=0)

  run_id = f"oracle-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
  with path.open("a", encoding="utf-8") as f:
    f.write(json.dumps({"event": "run_start", "run_id": run_id,
                        "operation": "can_oracle_capture",
                        "time_utc": datetime.now(UTC).isoformat(),
                        "sync_hypothesis": f"0x{SYNC_ADDR:03x}",
                        "protected_hypotheses": sorted(f"0x{a:03x}" for a in PROTECTED_ADDRS)}) + "\n")
    while time.monotonic() - begin < seconds:
      frames = panda.can_recv()
      if not frames:
        time.sleep(0.005)
        continue

      ts_ms = (time.monotonic() - begin) * 1000.0
      for addr, *_, data, bus in frames:
        if bus >= 0x80:
          continue
        known_sync = addr == SYNC_ADDR
        known_protected = addr in PROTECTED_ADDRS
        f.write(json.dumps({"event": "can", "run_id": run_id,
                            "addr": int(addr), "bus": int(bus), "len": len(data),
                            "ts_ms": ts_ms, "t_mono_ns": time.monotonic_ns(),
                            "t_wall_ns": time.time_ns(),
                            "data": bytes(data).hex(),
                            "annotation": ("prior_sync_hypothesis" if known_sync else
                                           "prior_protected_hypothesis" if known_protected else "")}) + "\n")
        if known_sync:
          sync_count += 1
        elif known_protected:
          protected_count += 1

      now = time.monotonic()
      if now - last_progress >= 1.0:
        last_progress = now
        f.flush()
        cb(seconds=now - begin, sync=sync_count, protected=protected_count)

      # Stop as soon as both targets are met. Sync is the bottleneck (~10/s) while
      # protected floods (~100/s), so this exits with hundreds of protected samples,
      # far above the matcher floor. The seconds cap still bounds a slow/sparse bus.
      if sync_count >= SYNC_TARGET and protected_count >= PROTECTED_TARGET:
        break

    f.write(json.dumps({"event": "run_end", "run_id": run_id,
                        "operation": "can_oracle_capture", "sync": sync_count,
                        "protected": protected_count}) + "\n")
    f.flush()
    os.fsync(f.fileno())

  cb(seconds=time.monotonic() - begin, sync=sync_count, protected=protected_count)

  if sync_count >= SYNC_TARGET and protected_count >= PROTECTED_TARGET:
    return {
      "status": "complete",
      "sync": sync_count,
      "protected": protected_count,
      "oracle_path": str(path),
      "message": f"Collected {sync_count} sync and {protected_count} protected frames.",
    }
  return {
    "status": "insufficient",
    "sync": sync_count,
    "protected": protected_count,
    "oracle_path": str(path),
    "message": " ".join((
      f"Only {sync_count}/{SYNC_TARGET} sync and {protected_count}/{PROTECTED_TARGET} protected frames.",
      "Put the car in READY Mode (hybrid on) and collect again.",
    )),
  }
