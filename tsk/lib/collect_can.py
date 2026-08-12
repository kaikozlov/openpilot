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

from tsk.lib.diagnostic_route import ELM327_NORMAL_PARAM, configure_elm327
from tsk.lib.env import CAN_ORACLE_PATH, is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.secoc_discovery import load_oracle_discovery
from tsk.lib.secoc_profile import (
  CLASSIC_PROTECTED_ADDRS, CURRENT_OPENPILOT_LATERAL_PROTECTED_ADDRS,
  CURRENT_OPENPILOT_LONGITUDINAL_PROTECTED_ADDRS, SYNC_ADDR,
)

PROTECTED_ADDRS = CLASSIC_PROTECTED_ADDRS
# Known classic Toyota SecOC IDs are annotations/matcher inputs only. Capture itself
# remains unfiltered across all buses and arbitration IDs.

# UI/ready thresholds (raw frame counts, matching the index row's "N/50", "N/30").
SYNC_TARGET = 50
PROTECTED_TARGET = 30
CONTROL_SAMPLE_TARGET = 2
COLLECT_SECONDS = 60.0  # full observation window; target discovery must not stop on legacy IDs


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

  # Kill the manager so pandad doesn't fight for the panda (mirrors dump()).
  subprocess.run(["pkill", "-9", "-f", "manager.py"], check=False)
  subprocess.run(["pkill", "-9", "-f", "pandad"], check=False)
  time.sleep(2)

  panda = TSKExtractor._connect_panda()
  configure_elm327(panda, ELM327_NORMAL_PARAM)

  path = oracle_path()
  path.parent.mkdir(parents=True, exist_ok=True)

  sync_count = 0
  protected_count = 0
  protected_by_id = {addr: 0 for addr in sorted(PROTECTED_ADDRS)}
  counts_by_bus: dict[int, dict[str, int]] = {}
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
          counts_by_bus.setdefault(int(bus), {"sync": 0, "protected": 0})["sync"] += 1
        elif known_protected:
          protected_count += 1
          protected_by_id[int(addr)] += 1
          counts_by_bus.setdefault(int(bus), {"sync": 0, "protected": 0})["protected"] += 1

      now = time.monotonic()
      if now - last_progress >= 1.0:
        last_progress = now
        f.flush()
        cb(seconds=now - begin, sync=sync_count, protected=protected_count)

      # Deliberately no early stop here. The current openpilot IDs are compatibility
      # evidence, not the discovery boundary for an unknown target. Keep the full
      # observation window so slower or previously unknown SecOC streams can emerge.

    legacy_lateral_observed = all(
      protected_by_id.get(addr, 0) >= CONTROL_SAMPLE_TARGET
      for addr in CURRENT_OPENPILOT_LATERAL_PROTECTED_ADDRS
    )
    legacy_lateral_counts = {
      f"0x{addr:03x}": protected_by_id.get(addr, 0)
      for addr in sorted(CURRENT_OPENPILOT_LATERAL_PROTECTED_ADDRS)
    }
    legacy_longitudinal_observed = all(
      protected_by_id.get(addr, 0) >= CONTROL_SAMPLE_TARGET
      for addr in CURRENT_OPENPILOT_LONGITUDINAL_PROTECTED_ADDRS
    )
    legacy_longitudinal_counts = {
      f"0x{addr:03x}": protected_by_id.get(addr, 0)
      for addr in sorted(CURRENT_OPENPILOT_LONGITUDINAL_PROTECTED_ADDRS)
    }
    f.write(json.dumps({"event": "run_end", "run_id": run_id,
                        "operation": "can_oracle_capture", "sync": sync_count,
                        "protected": protected_count,
                        "protected_by_id": {f"0x{k:03x}": v for k, v in protected_by_id.items() if v},
                        "counts_by_bus": counts_by_bus,
                        "legacy_lateral_observed": legacy_lateral_observed,
                        "legacy_lateral_counts": legacy_lateral_counts,
                        "legacy_longitudinal_observed": legacy_longitudinal_observed,
                        "legacy_longitudinal_counts": legacy_longitudinal_counts,
                        "elm327_param": ELM327_NORMAL_PARAM,
                        "semantic_path": "normal-harness"}) + "\n")
    f.flush()
    os.fsync(f.fileno())

  cb(seconds=time.monotonic() - begin, sync=sync_count, protected=protected_count)
  discovery = load_oracle_discovery(path, run_id=run_id)
  discovered_streams = [row for row in discovery["streams"] if row["scan_included"]]
  discovered_samples = sum(int(row["samples"]) for row in discovered_streams)
  discovery_ready = sync_count >= SYNC_TARGET and discovered_samples >= PROTECTED_TARGET

  common = {
    "sync": sync_count,
    "protected": protected_count,
    "protected_by_id": {f"0x{k:03x}": v for k, v in protected_by_id.items() if v},
    "counts_by_bus": counts_by_bus,
    "legacy_lateral_observed": legacy_lateral_observed,
    "legacy_lateral_counts": legacy_lateral_counts,
    "legacy_longitudinal_observed": legacy_longitudinal_observed,
    "legacy_longitudinal_counts": legacy_longitudinal_counts,
    # Compatibility aliases for the existing UI while it is migrated.
    "control_ready": legacy_lateral_observed,
    "control_counts": legacy_lateral_counts,
    "profile_discovery": {
      "streams": discovery["streams"],
      "can_inventory": discovery["can_inventory"],
      "unknown_structural_candidates": discovery["unknown_structural_candidates"],
      "unknown_scan_streams": discovery["unknown_scan_streams"],
      "scan_included_samples": discovered_samples,
    },
    "elm327_param": ELM327_NORMAL_PARAM,
    "semantic_path": "normal-harness",
    "oracle_path": str(path),
  }

  if discovery_ready:
    return {
      "status": "complete",
      **common,
      "message": (f"Collected {sync_count} sync frames and {discovered_samples} structurally eligible classic SecOC samples "
                  f"across {len(discovered_streams)} stream(s). Target-profile evidence is ready for cryptographic classification."),
    }
  return {
    "status": "insufficient",
    **common,
    "message": " ".join((
      f"Only {sync_count}/{SYNC_TARGET} sync and {discovered_samples}/{PROTECTED_TARGET} structurally eligible classic SecOC samples.",
      "Put the car in READY Mode (hybrid on) and collect again.",
    )),
  }
