#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from openpilot.cereal import messaging
from openpilot.common.params import Params
from openpilot.common.swaglog import cloudlog
from openpilot.common.utils import atomic_write
from opendbc.car.structs import car
from opendbc.car.toyota.values import CAR

TOOL_PATH = Path(os.getenv("TSS3_ORACLE_TOOL", "/data/tss3-oracle/tss3-unified-signer"))
RUN_ROOT = Path(os.getenv("TSS3_ORACLE_RUN_ROOT", "/data/tss3-oracle-runs"))
STATUS_PATH = Path(os.getenv("TSS3_ORACLE_AUTO_STATUS", "/data/tss3-oracle-auto-status.json"))
STATUS_SCHEMA = "tss3-oracle-auto-arm-status-v1"
BACKEND_STATUS_SCHEMA = "camry-f33-oracle-ui-status-v1"

_exit_requested = False
_child: subprocess.Popen[str] | None = None
_child_lock = threading.Lock()


def _write_status(state: str, detail: str, **extra: Any) -> None:
  status: dict[str, Any] = {
    "schema": STATUS_SCHEMA,
    "state": state,
    "detail": detail,
    "monotonic_ns": time.monotonic_ns(),
    **extra,
  }
  STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
  with atomic_write(str(STATUS_PATH), "w", overwrite=True) as f:
    json.dump(status, f, indent=2, sort_keys=True)
    f.write("\n")


def _exact_f33(params: Params) -> bool:
  raw = params.get("CarParamsPersistent")
  if raw is None:
    return False
  try:
    cp = messaging.log_from_bytes(raw, car.CarParams)
  except Exception:
    cloudlog.exception("tss3oracled.invalid_persistent_carparams")
    return False
  return cp.carFingerprint == CAR.TOYOTA_CAMRY_TSS3


def _terminate_child() -> None:
  with _child_lock:
    proc = _child
  if proc is None or proc.poll() is not None:
    return
  try:
    os.killpg(proc.pid, signal.SIGTERM)
  except ProcessLookupError:
    pass


def _signal_handler(signum, _frame) -> None:
  global _exit_requested
  cloudlog.info(f"tss3oracled caught signal {signum}")
  _exit_requested = True
  _terminate_child()


def _record_trigger_timing(run_dir: Path, trigger_fallback: Path, *, ignition_log_mono_ns: int, ignition_received_ns: int,
                           backend_launch_ns: int, returncode: int) -> dict[str, Any]:
  record: dict[str, Any] = {
    "schema": "tss3-oracle-auto-arm-trigger-v1",
    "ignition_panda_states_log_mono_ns": ignition_log_mono_ns,
    "ignition_daemon_received_monotonic_ns": ignition_received_ns,
    "backend_launch_monotonic_ns": backend_launch_ns,
    "panda_states_delivery_ms": (ignition_received_ns - ignition_log_mono_ns) / 1e6,
    "daemon_to_backend_launch_ms": (backend_launch_ns - ignition_received_ns) / 1e6,
    "returncode": returncode,
  }

  startup_path = run_dir / "startup-programming.json"
  if startup_path.is_file():
    try:
      startup = json.loads(startup_path.read_text(encoding="utf-8"))
      for key, out_key in (
        ("start_monotonic_ns", "ignition_to_worker_start_ms"),
        ("armed_monotonic_ns", "ignition_to_worker_armed_ms"),
        ("positive_extended_monotonic_ns", "ignition_to_first_50_03_ms"),
        ("programming_tx_monotonic_ns", "ignition_to_10_02_ms"),
      ):
        value = startup.get(key)
        if isinstance(value, int):
          record[out_key] = (value - ignition_log_mono_ns) / 1e6
    except (OSError, json.JSONDecodeError):
      cloudlog.exception("tss3oracled.trigger_timing_parse_failed")

  trigger_path = (run_dir / "auto-trigger.json") if run_dir.is_dir() else trigger_fallback
  with atomic_write(str(trigger_path), "w", overwrite=True) as f:
    json.dump(record, f, indent=2, sort_keys=True)
    f.write("\n")
  return record


def _allocate_run_path(*, stamp: str, ignition_received_ns: int) -> tuple[Path, Path, Path]:
  """Choose fresh paths without creating the backend-owned output directory."""
  base = f"auto-{stamp}-{ignition_received_ns}"
  suffix = 0
  while True:
    name = base if suffix == 0 else f"{base}-{suffix}"
    run_dir = RUN_ROOT / name
    log_path = RUN_ROOT / f"{name}.auto-daemon.log"
    trigger_fallback = RUN_ROOT / f"{name}.auto-trigger.json"
    if not run_dir.exists() and not log_path.exists() and not trigger_fallback.exists():
      return run_dir, log_path, trigger_fallback
    suffix += 1


def _run_bringup(*, ignition_log_mono_ns: int, ignition_received_ns: int) -> bool:
  global _child
  if not TOOL_PATH.is_file() or not os.access(TOOL_PATH, os.X_OK):
    _write_status("error", f"oracle tool unavailable: {TOOL_PATH}")
    return False

  stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime())
  RUN_ROOT.mkdir(parents=True, exist_ok=True)
  run_dir, log_path, trigger_fallback = _allocate_run_path(stamp=stamp, ignition_received_ns=ignition_received_ns)
  cmd = [str(TOOL_PATH), "--topology", "camry-post-repin", "oracle-ui-bringup", str(run_dir)]
  launch_ns = time.monotonic_ns()

  _write_status(
    "triggered",
    "Panda ignition rising edge detected; starting exact-F33 oracle bringup.",
    run_dir=str(run_dir),
    auto_daemon_log=str(log_path),
    ignition_panda_states_log_mono_ns=ignition_log_mono_ns,
    ignition_daemon_received_monotonic_ns=ignition_received_ns,
    backend_launch_monotonic_ns=launch_ns,
  )
  cloudlog.warning(f"tss3oracled triggering startup bringup: {run_dir}")

  try:
    proc = subprocess.Popen(
      cmd,
      cwd=str(TOOL_PATH.parent),
      stdin=subprocess.DEVNULL,
      stdout=subprocess.PIPE,
      stderr=subprocess.STDOUT,
      text=True,
      bufsize=1,
      start_new_session=True,
    )
  except OSError as exc:
    _write_status("error", f"failed to launch oracle bringup: {type(exc).__name__}: {exc}", run_dir=str(run_dir))
    return False

  with _child_lock:
    _child = proc

  latest_backend_status: dict[str, Any] | None = None
  try:
    assert proc.stdout is not None
    with log_path.open("w", encoding="utf-8") as log:
      for raw in proc.stdout:
        log.write(raw)
        log.flush()
        line = raw.strip()
        if not line:
          continue
        try:
          row = json.loads(line)
        except json.JSONDecodeError:
          continue
        if isinstance(row, dict) and row.get("schema") == BACKEND_STATUS_SCHEMA:
          latest_backend_status = row
          _write_status(
            "running",
            str(row.get("detail", row.get("title", "oracle bringup running"))),
            run_dir=str(run_dir),
            backend_stage=row.get("stage"),
            backend_progress=row.get("progress"),
            backend_done=bool(row.get("done")),
            backend_error=bool(row.get("error")),
          )

    returncode = proc.wait()
  finally:
    with _child_lock:
      _child = None

  timing = _record_trigger_timing(
    run_dir, trigger_fallback,
    ignition_log_mono_ns=ignition_log_mono_ns,
    ignition_received_ns=ignition_received_ns,
    backend_launch_ns=launch_ns,
    returncode=returncode,
  )

  summary_path = run_dir / "summary.json"
  success = returncode == 0 and summary_path.is_file()
  if success:
    try:
      summary = json.loads(summary_path.read_text(encoding="utf-8"))
      success = summary.get("verdict") == "startup_caught_oracle_resident_peer_state_healthy_known_answer_pass"
    except (OSError, json.JSONDecodeError):
      success = False

  if success:
    _write_status(
      "complete",
      "Automatic TSS3 oracle bringup passed.",
      run_dir=str(run_dir),
      trigger_timing=timing,
    )
  else:
    detail = "Automatic TSS3 oracle bringup failed."
    if latest_backend_status is not None:
      detail = str(latest_backend_status.get("detail", detail))
    _write_status(
      "error",
      detail,
      run_dir=str(run_dir),
      returncode=returncode,
      trigger_timing=timing,
    )
  return success


def main() -> None:
  global _exit_requested
  signal.signal(signal.SIGINT, _signal_handler)
  signal.signal(signal.SIGTERM, _signal_handler)

  params = Params()
  sm = messaging.SubMaster(["pandaStates"], poll="pandaStates")
  initialized = False
  last_ignition = False

  _write_status("starting", "Automatic TSS3 oracle watcher starting.")

  try:
    while not _exit_requested:
      sm.update(1000)
      if not sm.updated["pandaStates"]:
        continue

      panda_states = list(sm["pandaStates"])
      if not panda_states:
        continue

      ignition = any(p.ignitionLine or p.ignitionCan for p in panda_states)
      received_ns = time.monotonic_ns()
      log_mono_ns = int(sm.logMonoTime["pandaStates"])

      if not initialized:
        initialized = True
        last_ignition = ignition
        state = "waiting_off" if ignition else "armed"
        detail = ("Watcher started while ignition was already on; waiting for the next OFF→ON edge."
                  if ignition else "Automatic TSS3 oracle armed; waiting for Panda ignition.")
        _write_status(state, detail, exact_f33=_exact_f33(params))
        continue

      rising = ignition and not last_ignition
      falling = not ignition and last_ignition
      last_ignition = ignition

      if falling:
        _write_status("armed", "Automatic TSS3 oracle armed; waiting for Panda ignition.", exact_f33=_exact_f33(params))
        continue

      if not rising:
        continue

      if not _exact_f33(params):
        _write_status("ignored", "Ignition edge ignored: persistent CarParams is not exact TOYOTA_CAMRY_TSS3.")
        continue

      _run_bringup(ignition_log_mono_ns=log_mono_ns, ignition_received_ns=received_ns)
  finally:
    _terminate_child()


if __name__ == "__main__":
  main()
