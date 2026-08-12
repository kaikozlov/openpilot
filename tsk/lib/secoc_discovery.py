#!/usr/bin/env python3
"""Discover classic Toyota SecOC stream candidates from an unfiltered CAN oracle.

The capture path intentionally records every received frame. This module is the
pure/offline classification layer: it keeps prior Toyota protected-ID hypotheses,
but it can also surface an unknown 8-byte stream when its trailer behaves like the
classic Toyota SecOC format relative to the most recent 0x00F synchronization frame
on the same bus/run.

Structural classification is *not* authentication. The matcher must still prove a
candidate with AES-CMAC before any key or stream is trusted.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from tsk.lib.secoc_profile import ADDITIONAL_PROTECTED_HYPOTHESES, CLASSIC_PROTECTED_ADDRS, SYNC_ADDR

MAX_SYNC_SAMPLES = 1024
MAX_PROTECTED_PER_ADDR = 250
MIN_STRUCTURAL_SAMPLES = 8
MIN_RESET_FLAG_AGREEMENT = 0.875
MIN_AUTH_DISTINCT_RATIO = 0.50
MIN_MSG_COUNTER_VALUES = 2
MAX_UNKNOWN_SCAN_STREAMS = 24


@dataclass
@dataclass
class _InventoryStream:
  bus: int
  addr: int
  length: int
  samples: int = 0
  first_ms: float | None = None
  last_ms: float | None = None

  def observe(self, rel_ms: float | None) -> None:
    self.samples += 1
    if rel_ms is not None:
      if self.first_ms is None or rel_ms < self.first_ms:
        self.first_ms = rel_ms
      if self.last_ms is None or rel_ms > self.last_ms:
        self.last_ms = rel_ms

  def summary(self) -> dict:
    rate_hz = None
    if self.first_ms is not None and self.last_ms is not None and self.last_ms > self.first_ms:
      rate_hz = round(max(0, self.samples - 1) / ((self.last_ms - self.first_ms) / 1000.0), 3)
    return {
      "bus": self.bus,
      "addr": f"0x{self.addr:03x}",
      "addr_int": self.addr,
      "length": self.length,
      "samples": self.samples,
      "rate_hz": rate_hz,
      "sync_hypothesis": self.addr == SYNC_ADDR,
      "known_classic_secoc_hypothesis": self.addr in CLASSIC_PROTECTED_ADDRS,
      "known_additional_secoc_hypothesis": self.addr in ADDITIONAL_PROTECTED_HYPOTHESES,
    }


@dataclass
class _Stream:
  bus: int
  addr: int
  samples: list[dict] = field(default_factory=list)
  raw_count: int = 0
  reset_matches: int = 0
  auth_values: set[int] = field(default_factory=set)
  msg_counter_values: set[int] = field(default_factory=set)
  lengths: set[int] = field(default_factory=set)
  first_ms: float | None = None
  last_ms: float | None = None

  def observe(self, sample: dict, *, length: int, rel_ms: float | None) -> None:
    self.raw_count += 1
    self.lengths.add(length)
    flag = int(sample["flag"])
    reset = int(sample["reset"])
    if (flag & 3) == (reset & 3):
      self.reset_matches += 1
    self.auth_values.add(int(sample["auth"]))
    self.msg_counter_values.add((flag >> 2) & 3)
    if rel_ms is not None:
      if self.first_ms is None or rel_ms < self.first_ms:
        self.first_ms = rel_ms
      if self.last_ms is None or rel_ms > self.last_ms:
        self.last_ms = rel_ms
    if len(self.samples) < MAX_PROTECTED_PER_ADDR:
      self.samples.append(sample)

  def summary(self) -> dict:
    sample_count = self.raw_count
    reset_ratio = self.reset_matches / sample_count if sample_count else 0.0
    auth_ratio = len(self.auth_values) / sample_count if sample_count else 0.0
    known = self.addr in CLASSIC_PROTECTED_ADDRS
    structural = (
      sample_count >= MIN_STRUCTURAL_SAMPLES
      and reset_ratio >= MIN_RESET_FLAG_AGREEMENT
      and len(self.msg_counter_values) >= MIN_MSG_COUNTER_VALUES
      and auth_ratio >= MIN_AUTH_DISTINCT_RATIO
      and self.lengths == {8}
    )
    duration_s = 0.0
    rate_hz = None
    if self.first_ms is not None and self.last_ms is not None and self.last_ms > self.first_ms:
      duration_s = (self.last_ms - self.first_ms) / 1000.0
      rate_hz = round(max(0, sample_count - 1) / duration_s, 3)
    return {
      "bus": self.bus,
      "addr": f"0x{self.addr:03x}",
      "addr_int": self.addr,
      "samples": sample_count,
      "lengths": sorted(self.lengths),
      "reset_flag_agreement": round(reset_ratio, 6),
      "msg_counter_low2_values": sorted(self.msg_counter_values),
      "authenticator_distinct": len(self.auth_values),
      "authenticator_distinct_ratio": round(auth_ratio, 6),
      "known_toyota_hypothesis": known,
      "structural_candidate": structural,
      "rate_hz": rate_hz,
    }


def _tail28(data: bytes) -> int:
  return (((data[4] & 0x0F) << 24) | (data[5] << 16) | (data[6] << 8) | data[7]) & 0x0FFFFFFF


def _relative_ms(record: dict) -> float | None:
  for key in ("ts_ms", "t_rel_ms"):
    try:
      value = record.get(key)
      if value is not None:
        return float(value)
    except (TypeError, ValueError):
      pass
  return None


def load_oracle_discovery(path: Path, *, run_id: str | None = None) -> dict:
  """Parse one append-only oracle into sync samples and candidate classic streams.

  Known classic Toyota IDs are always retained when they have same-run/same-bus
  synchronization context. Unknown IDs are admitted only by the structural trailer
  predicate above. Candidate ranking limits only exhaustive-scan probes; every stream
  remains in ``streams`` for target-profile evidence.
  """
  sync_samples: list[dict] = []
  sync_by_bus: dict[int, tuple[int, int, int]] = {}
  sync_seen: set[tuple[int, int, int, int]] = set()
  streams: dict[tuple[int, int], _Stream] = {}
  can_inventory: dict[tuple[int, int, int], _InventoryStream] = {}
  malformed = 0

  with Path(path).open("r", encoding="utf-8") as fh:
    for line in fh:
      if not line.strip():
        continue
      try:
        record = json.loads(line)
      except json.JSONDecodeError:
        malformed += 1
        continue
      if run_id is not None and record.get("run_id") != run_id:
        continue
      if record.get("event") == "run_start":
        sync_by_bus.clear()
        continue
      if record.get("event") not in (None, "can"):
        continue
      try:
        addr = int(record["addr"])
        bus = int(record["bus"])
        data = bytes.fromhex(str(record["data"]))
      except (KeyError, TypeError, ValueError):
        malformed += 1
        continue
      rel_ms = _relative_ms(record)
      inventory_key = (bus, addr, len(data))
      can_inventory.setdefault(
        inventory_key, _InventoryStream(bus=bus, addr=addr, length=len(data))
      ).observe(rel_ms)
      if len(data) < 8:
        continue

      if addr == SYNC_ADDR and len(data) == 8:
        trip = int.from_bytes(data[0:2], "big")
        reset = (data[2] << 12) | (data[3] << 4) | (data[4] >> 4)
        auth = _tail28(data)
        sync_by_bus[bus] = (trip, reset, auth)
        identity = (bus, trip, reset, auth)
        if identity not in sync_seen and len(sync_samples) < MAX_SYNC_SAMPLES:
          sync_seen.add(identity)
          sync_samples.append({"bus": bus, "trip": trip, "reset": reset, "auth": auth})
        continue

      # The classic protected format is exactly 8 bytes. Keep larger frames in the
      # capture/profile census elsewhere; do not reinterpret a CAN-FD suffix as a
      # classic SecOC trailer.
      if len(data) != 8 or bus not in sync_by_bus:
        continue
      trip, reset, _ = sync_by_bus[bus]
      sample = {
        "addr": addr,
        "bus": bus,
        "payload4": data[:4],
        "flag": data[4] >> 4,
        "auth": _tail28(data),
        "trip": trip,
        "reset": reset,
      }
      stream = streams.setdefault((bus, addr), _Stream(bus=bus, addr=addr))
      stream.observe(sample, length=len(data), rel_ms=rel_ms)

  summaries = [stream.summary() for _, stream in sorted(streams.items())]
  unknown_candidates = [
    summary for summary in summaries
    if summary["structural_candidate"] and not summary["known_toyota_hypothesis"]
  ]
  # Strongest structural candidates first; deterministic ties by bus/address.
  unknown_candidates.sort(key=lambda row: (
    -float(row["reset_flag_agreement"]),
    -len(row["msg_counter_low2_values"]),
    -float(row["authenticator_distinct_ratio"]),
    -int(row["samples"]),
    int(row["bus"]),
    int(row["addr_int"]),
  ))
  admitted_unknown = {
    (int(row["bus"]), int(row["addr_int"]))
    for row in unknown_candidates[:MAX_UNKNOWN_SCAN_STREAMS]
  }

  protected_samples: list[dict] = []
  for key, stream in sorted(streams.items()):
    summary = stream.summary()
    include = summary["known_toyota_hypothesis"] or key in admitted_unknown
    summary["scan_included"] = include
    if include:
      protected_samples.extend(stream.samples)

  # Rebuild the summaries once to attach the scan-inclusion disposition without
  # exposing mutable dataclass state to callers.
  summary_by_key = {(row["bus"], row["addr_int"]): row for row in summaries}
  for key, row in summary_by_key.items():
    row["scan_included"] = row["known_toyota_hypothesis"] or key in admitted_unknown

  return {
    "sync_samples": sync_samples,
    "protected_samples": protected_samples,
    "streams": [summary_by_key[key] for key in sorted(summary_by_key)],
    "can_inventory": [can_inventory[key].summary() for key in sorted(can_inventory)],
    "malformed": malformed,
    "unknown_structural_candidates": len(unknown_candidates),
    "unknown_scan_streams": len(admitted_unknown),
  }
