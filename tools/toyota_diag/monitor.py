"""Live Data List monitor rendering and structured logging."""
from __future__ import annotations

import csv
import json
import sys
import time
from typing import Any, TextIO

from tools.toyota_diag.discovery import flatten_signal_record


def _cell(value: Any) -> str:
  if value is None:
    return ""
  if isinstance(value, float):
    return f"{value:g}"
  return str(value)


def _row_key(row: dict[str, Any]) -> tuple[Any, ...]:
  return row.get("did"), row.get("signal")


def _row_state(row: dict[str, Any]) -> tuple[Any, ...]:
  return row.get("value"), row.get("raw"), row.get("error")


def render_table(ecu_name: str, sample: int, elapsed: float, values: list[dict[str, Any]], *, changed: bool = False,
                 previous: dict[tuple[Any, ...], tuple[Any, ...]] | None = None) -> tuple[str, dict[tuple[Any, ...], tuple[Any, ...]]]:
  rows = [row for value in values for row in flatten_signal_record(value)]
  state = {_row_key(row): _row_state(row) for row in rows}
  if changed and previous is not None:
    rows = [row for row in rows if previous.get(_row_key(row)) != _row_state(row)]

  lines = [f"{ecu_name}  sample={sample}  +{elapsed:.3f}s"]
  if not rows:
    lines.append("  (no changes)")
    return "\n".join(lines), state
  signal_width = max(18, min(46, max(len(str(row.get("signal") or "")) for row in rows)))
  lines.append(f"{'DID':<8} {'Signal':<{signal_width}} {'Value':<22} Unit")
  lines.append(f"{'-' * 6:<8} {'-' * min(signal_width, 24):<{signal_width}} {'-' * 18:<22} {'-' * 8}")
  for row in rows:
    did = f"0x{int(row['did']):04X}" if row.get("did") is not None else "-"
    value = f"ERR: {row['error']}" if row.get("error") else _cell(row.get("value"))
    lines.append(f"{did:<8} {str(row.get('signal') or ''):<{signal_width}} {value:<22} {_cell(row.get('unit'))}")
  return "\n".join(lines), state


def emit_jsonl(stream: TextIO, sample: int, elapsed: float, values: list[dict[str, Any]]) -> None:
  print(json.dumps({"sample": sample, "elapsed_s": round(elapsed, 6), "values": values}, sort_keys=True), file=stream)


def emit_csv(writer: csv.DictWriter, sample: int, elapsed: float, values: list[dict[str, Any]]) -> None:
  for value in values:
    for row in flatten_signal_record(value):
      writer.writerow({
        "sample": sample,
        "elapsed_s": round(elapsed, 6),
        "ecu": row.get("ecu"),
        "did": f"0x{int(row['did']):04X}" if row.get("did") is not None else "",
        "signal": row.get("signal"),
        "value": row.get("value"),
        "numeric_value": row.get("numeric_value"),
        "pattern": row.get("pattern"),
        "raw": row.get("raw"),
        "unit": row.get("unit"),
        "error": row.get("error"),
      })


def run(ecu_name: str, read_values, *, interval: float, count: int, changed: bool, jsonl: bool, csv_output: bool,
        clear: bool | None = None, stream: TextIO | None = None) -> int:
  if interval < 0:
    raise ValueError("--interval must be >= 0")
  if count < 0:
    raise ValueError("--count must be >= 0 (0 means until interrupted)")
  if jsonl and csv_output:
    raise ValueError("--jsonl and --csv are mutually exclusive")
  stream = sys.stdout if stream is None else stream
  if clear is None:
    clear = bool(getattr(stream, "isatty", lambda: False)()) and not jsonl and not csv_output and not changed

  writer = None
  if csv_output:
    fields = ["sample", "elapsed_s", "ecu", "did", "signal", "value", "numeric_value", "pattern", "raw", "unit", "error"]
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()

  started = time.monotonic()
  sample = 0
  previous = None
  try:
    while count == 0 or sample < count:
      sample += 1
      values = read_values()
      elapsed = time.monotonic() - started
      if jsonl:
        emit_jsonl(stream, sample, elapsed, values)
      elif writer is not None:
        emit_csv(writer, sample, elapsed, values)
      else:
        text, state = render_table(ecu_name, sample, elapsed, values, changed=changed, previous=previous)
        previous = state
        if clear:
          stream.write("\x1b[2J\x1b[H")
        stream.write(text + "\n")
        stream.flush()
      if count == 0 or sample < count:
        time.sleep(interval)
  except KeyboardInterrupt:
    if not jsonl and not csv_output:
      print("stopped", file=stream)
  return 0
