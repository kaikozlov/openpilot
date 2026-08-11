#!/usr/bin/env python3
"""READY-mode evidence collection.

This module intentionally separates two operations:

* ``capture_ready`` is passive. It receives every CAN frame on every Panda bus,
  preserves complete payloads in an append-only NDJSON transcript, and sends no
  diagnostic traffic.
* ``run_ready_diff`` is active. It replays only bare service requests that were
  already observed as silent or condition-gated by a prior Not Ready to Drive
  sweep. It never invents a request from a Sienna/Corolla hypothesis.

Both operations are AGNOS-gated; their pure parsing helpers remain testable on a
workstation.
"""
import json
import os
import subprocess
import time
from collections.abc import Iterable
from datetime import datetime, UTC
from pathlib import Path
from uuid import uuid4

from tsk.lib.env import CACHE_DIR, is_agnos
from tsk.lib.extractor import NotAGNOSError, TSKExtractor
from tsk.lib.dump_dataflash import ADDR
from tsk.lib.dump_diag import CANDIDATE_BUSES
from tsk.lib.diagnostic_route import (
  ELM327_NORMAL_PARAM, configure_elm327, discover_eps_route_with_routing,
)
from tsk.lib.secoc_profile import CAPTURE_PROTECTED_HYPOTHESES, SYNC_ADDR
from tsk.lib.sweep_uds import SWEEP_PATH, ask

CAPTURE_DIR = f"{CACHE_DIR}/tsk/uds-sweep"
CAPTURE_PATH = f"{CAPTURE_DIR}/ready_capture.ndjson"
DIFF_PATH = f"{CAPTURE_DIR}/ready_diff.ndjson"

CAPTURE_SECONDS = 90.0
TIMEOUT = 0.2
CONDITION_NRCS = {0x22, 0x7E, 0x7F}
SYNC_HYPOTHESES = {SYNC_ADDR}
PROTECTED_ID_HYPOTHESES = set(CAPTURE_PROTECTED_HYPOTHESES)


def _noop(**kwargs) -> None:
  pass


def _run_id(prefix: str) -> str:
  stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
  return f"{prefix}-{stamp}-{uuid4().hex[:8]}"


def _append_record(fh, record: dict) -> None:
  fh.write(json.dumps(record, sort_keys=True) + "\n")


def analyze_capture(frames: list, min_samples: int = 8) -> dict:
  """Flag candidate authenticated frames without filtering capture input.

  ``frames`` contains ``(bus, address, hex_payload)`` tuples. Known Toyota IDs
  are returned as annotations only; all arbitration IDs participate in the
  structural tail/head analysis.
  """
  by_id: dict = {}
  for bus, addr, payload in frames:
    by_id.setdefault((bus, addr), []).append(payload)

  out = {
    "candidates": [],
    "hypothesis_hits": [],
    "sync": [],
    "ids": len(by_id),
    "frames": len(frames),
  }
  for (bus, addr), samples in sorted(by_id.items()):
    if addr in SYNC_HYPOTHESES:
      out["sync"].append({
        "bus": bus,
        "addr": f"0x{addr:03x}",
        "samples": len(samples),
        "distinct": len(set(samples)),
        "annotation": "prior Toyota sync hypothesis",
      })
    if addr in PROTECTED_ID_HYPOTHESES:
      out["hypothesis_hits"].append({
        "bus": bus,
        "addr": f"0x{addr:03x}",
        "samples": len(samples),
        "annotation": "prior Sienna/Corolla protected-ID hypothesis",
      })
    if len(samples) < min_samples:
      continue
    width = min(len(s) for s in samples) // 2
    if width < 4:
      continue
    tail = [s[-8:] for s in samples]
    head = [s[:-8] for s in samples]
    tail_ratio = len(set(tail)) / len(tail)
    head_ratio = len(set(head)) / len(head)
    if tail_ratio >= 0.9 and tail_ratio - head_ratio >= 0.3:
      out["candidates"].append({
        "bus": bus,
        "addr": f"0x{addr:03x}",
        "samples": len(samples),
        "tail_distinct": round(tail_ratio, 3),
        "head_distinct": round(head_ratio, 3),
      })
  out["candidates"].sort(key=lambda c: -c["samples"])
  return out


def build_mode_diff_worklist(path: str = SWEEP_PATH) -> list[tuple[bytes, str]]:
  """Return exact, previously characterized bare-service requests.

  Only ``svc:`` records from the Not Ready to Drive sweep qualify. This keeps
  the READY comparison useful without replaying reset/write/download
  subfunctions merely because another calibration once used them.
  """
  selected: dict[str, tuple[bytes, str]] = {}
  try:
    fh = open(path, encoding="utf-8")
  except OSError:
    return []
  with fh:
    for line in fh:
      try:
        rec = json.loads(line)
        key = str(rec.get("key", ""))
        request_hex = str(rec.get("request", ""))
        outcome = rec.get("outcome")
        nrc = int(rec.get("nrc", -1))
        payload = bytes.fromhex(request_hex)
      except (ValueError, TypeError, json.JSONDecodeError):
        continue
      if not key.startswith("svc:") or len(payload) != 1:
        continue
      if outcome == "silent" or (outcome == "nrc" and nrc in CONDITION_NRCS):
        selected[request_hex] = (payload, str(rec.get("label", key)))
  return [selected[key] for key in sorted(selected)]


def _take_panda():
  subprocess.run(["pkill", "-9", "-f", "manager.py"], check=False)
  subprocess.run(["pkill", "-9", "-f", "pandad"], check=False)
  time.sleep(2)
  panda = TSKExtractor._connect_panda()
  configure_elm327(panda, ELM327_NORMAL_PARAM)
  return panda


def _panda_version(panda) -> str:
  try:
    value = panda.get_version()
    return value.decode(errors="replace") if isinstance(value, (bytes, bytearray)) else str(value)
  except Exception:
    return "unknown"


def capture_ready(progress_cb=None, seconds: float = CAPTURE_SECONDS) -> dict:
  """Passively capture every received CAN payload for ``seconds``."""
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop
  panda = _take_panda()
  panda_version = _panda_version(panda)
  Path(CAPTURE_DIR).mkdir(parents=True, exist_ok=True)

  run_id = _run_id("ready-passive")
  frames: list[tuple[int, int, str]] = []
  echoes = 0
  begin_mono = time.monotonic()
  last_report = begin_mono

  with open(CAPTURE_PATH, "a", encoding="utf-8") as fh:
    _append_record(fh, {
      "event": "run_start",
      "run_id": run_id,
      "operation": "ready_passive_capture",
      "time_utc": datetime.now(UTC).isoformat(),
      "panda": panda_version,
      "duration_requested_s": seconds,
    })
    fh.flush()
    while time.monotonic() - begin_mono < seconds:
      try:
        batch: Iterable = panda.can_recv()
      except Exception:
        break
      if not batch:
        time.sleep(0.005)
        continue
      for addr, *_rest, data, bus in batch:
        if bus >= 0x80:
          echoes += 1
          continue
        payload = bytes(data).hex()
        frames.append((int(bus), int(addr), payload))
        _append_record(fh, {
          "event": "can",
          "run_id": run_id,
          "t_mono_ns": time.monotonic_ns(),
          "t_wall_ns": time.time_ns(),
          "t_rel_ms": round((time.monotonic() - begin_mono) * 1000, 3),
          "bus": int(bus),
          "addr": int(addr),
          "len": len(data),
          "data": payload,
        })
      now = time.monotonic()
      if now - last_report >= 1.0:
        last_report = now
        fh.flush()
        cb(steps=len(frames), last=f"capturing {int(now - begin_mono)}s / {int(seconds)}s",
           stage="passive capture")
    elapsed = time.monotonic() - begin_mono
    _append_record(fh, {
      "event": "run_end",
      "run_id": run_id,
      "operation": "ready_passive_capture",
      "elapsed_s": round(elapsed, 3),
      "frames": len(frames),
      "tx_echoes_filtered": echoes,
    })
    fh.flush()
    os.fsync(fh.fileno())

  analysis = analyze_capture(frames)
  cb(steps=len(frames), last="passive capture analysed", stage="passive capture")
  return {
    "status": "captured",
    "mode": "passive",
    "run_id": run_id,
    "panda": panda_version,
    "eps_bus": -1,
    "elm327_param": ELM327_NORMAL_PARAM,
    "semantic_path": "normal-harness",
    "capture": analysis,
    "diff": [],
    "responders": [],
    "cross": [],
    "seeds": [],
    "frames": len(frames),
    "tx_echoes_filtered": echoes,
    "path": CAPTURE_PATH,
    "message": f"Passively captured {len(frames)} frames across {analysis['ids']} IDs. Filtered {echoes} Panda TX echoes. No diagnostic requests were sent.",
  }


def run_ready_diff(progress_cb=None, sweep_path: str = SWEEP_PATH) -> dict:
  """Replay prior bare-service observations as a separately invoked READY diff."""
  if not is_agnos():
    raise NotAGNOSError

  cb = progress_cb or _noop
  worklist = build_mode_diff_worklist(sweep_path)
  if not worklist:
    return {
      "status": "no_sweep",
      "mode": "active_diff",
      "panda": "",
      "eps_bus": -1,
      "diff": [],
      "frames": 0,
      "message": "No characterized bare-service worklist exists. Run the Not Ready to Drive sweep first.",
    }

  panda = _take_panda()
  panda_version = _panda_version(panda)
  route = discover_eps_route_with_routing(panda, CANDIDATE_BUSES, preferred_tx=ADDR)
  if route is None:
    return {
      "status": "unreachable",
      "mode": "active_diff",
      "panda": panda_version,
      "eps_bus": -1,
      "elm327_param": -1,
      "semantic_path": "",
      "diff": [],
      "frames": 0,
      "message": "The prior EPS route did not answer on buses 0, 1, or 2 under normal-harness or OBD routing.",
    }

  eps_tx = route["tx"]
  eps_bus = route["tx_bus"]
  eps_rx_bus = route["rx_bus"]
  eps_rx = route["rx"]

  def ask_eps(payload: bytes, request_timeout: float) -> dict:
    return ask(panda, eps_bus, eps_tx, eps_rx, payload, request_timeout,
               response_bus=eps_rx_bus)

  Path(CAPTURE_DIR).mkdir(parents=True, exist_ok=True)
  run_id = _run_id("ready-diff")
  diff: list[dict] = []
  with open(DIFF_PATH, "a", encoding="utf-8") as fh:
    _append_record(fh, {
      "event": "run_start",
      "run_id": run_id,
      "operation": "ready_active_diff",
      "time_utc": datetime.now(UTC).isoformat(),
      "panda": panda_version,
      "eps_tx": f"0x{eps_tx:03x}",
      "eps_bus": eps_bus,
      "eps_rx_bus": eps_rx_bus,
      "eps_rx": f"0x{eps_rx:03x}",
      "elm327_param": route["elm327_param"],
      "semantic_path": route["semantic_path"],
      "worklist_count": len(worklist),
    })
    for payload, label in worklist:
      response = ask_eps(payload, TIMEOUT)
      entry = {
        "event": "uds_result",
        "run_id": run_id,
        "label": label,
        "request": payload.hex(),
        "outcome": response["outcome"],
        "nrc": response["nrc"],
        "raw": response["raw"],
        "ms": response.get("ms", 0),
      }
      diff.append(entry)
      _append_record(fh, entry)
      cb(steps=len(diff), last=label, stage="active diff")
      # A known read serves as the liveness boundary after every replayed request.
      live = ask_eps(b"\x22\xf1\x81", TIMEOUT * 4)
      _append_record(fh, {
        "event": "liveness",
        "run_id": run_id,
        "after": payload.hex(),
        "outcome": live["outcome"],
        "nrc": live["nrc"],
        "raw": live["raw"],
        "ms": live.get("ms", 0),
      })
      fh.flush()
      if live["outcome"] not in ("positive", "nrc"):
        break
    restore = ask_eps(b"\x10\x01", TIMEOUT * 4)
    _append_record(fh, {
      "event": "restore",
      "run_id": run_id,
      "request": "1001",
      "outcome": restore["outcome"],
      "nrc": restore["nrc"],
      "raw": restore["raw"],
      "ms": restore.get("ms", 0),
    })
    _append_record(fh, {
      "event": "run_end",
      "run_id": run_id,
      "operation": "ready_active_diff",
      "results": len(diff),
    })
    fh.flush()
    os.fsync(fh.fileno())

  return {
    "status": "complete",
    "mode": "active_diff",
    "run_id": run_id,
    "panda": panda_version,
    "eps_tx": f"0x{eps_tx:03x}",
    "eps_bus": eps_bus,
    "eps_rx_bus": eps_rx_bus,
    "eps_rx": f"0x{eps_rx:03x}",
    "elm327_param": route["elm327_param"],
    "semantic_path": route["semantic_path"],
    "diff": diff,
    "frames": 0,
    "path": DIFF_PATH,
    "message": " ".join((
      f"Replayed {len(diff)} previously characterized bare-service request(s).",
      "No address sweep, SecurityAccess request, or unknown subfunction was sent.",
    )),
  }
