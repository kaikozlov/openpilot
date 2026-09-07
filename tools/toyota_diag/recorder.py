"""Derived Toyota TSS3 Operation/Image FFD protocol and decoder helpers.

The bundled metadata is clean, generated output from the current GTS+ native
plugins and PCS Data Viewer managed decoder.  This module intentionally exposes
only read-only recorder acquisition; it contains no delete/control operation.
"""
from __future__ import annotations

import json
import re
import struct
from functools import lru_cache
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).resolve().parent / "data"
PROTOCOL_PATH = DATA_DIR / "tss3_native_recorder_protocol.json"
SEMANTICS_PATH = DATA_DIR / "pcs_data_viewer_tss3_managed_semantics.json"


class RecorderError(ValueError):
  pass


@lru_cache(maxsize=1)
def protocol() -> dict[str, Any]:
  return json.loads(PROTOCOL_PATH.read_text())


@lru_cache(maxsize=1)
def semantics() -> dict[str, Any]:
  return json.loads(SEMANTICS_PATH.read_text())


@lru_cache(maxsize=1)
def _rows_by_did() -> dict[int, tuple[dict[str, Any], ...]]:
  grouped: dict[int, list[dict[str, Any]]] = {}
  for row in semantics()["operation_ffd"]["detail_rows"]:
    data_id = str(row.get("DataID") or "")
    if not data_id or data_id == "-":
      continue
    grouped.setdefault(int(data_id, 16), []).append(row)
  return {key: tuple(value) for key, value in grouped.items()}


@lru_cache(maxsize=1)
def _robs_by_code() -> dict[int, dict[str, Any]]:
  return {int(row["rob_code"], 16): row for row in semantics()["rob_codes"]["rows"]}


def signal_rows(data_id: int) -> tuple[dict[str, Any], ...]:
  return _rows_by_did().get(data_id, ())


def rob_row(code: int) -> dict[str, Any] | None:
  return _robs_by_code().get(code)


def _matches(query: str, text: str) -> bool:
  needle = query.casefold().strip()
  if not needle:
    return True
  hay = text.casefold()
  if needle in hay:
    return True
  query_tokens = re.findall(r"[a-z0-9]+", needle)
  hay_tokens = re.findall(r"[a-z0-9]+", hay)
  return bool(query_tokens) and all(any(token == item or item.startswith(token) for item in hay_tokens) for token in query_tokens)


def search_signals(query: str) -> list[tuple[int, dict[str, Any]]]:
  rows: list[tuple[int, dict[str, Any]]] = []
  for data_id, signals in _rows_by_did().items():
    for row in signals:
      if _matches(query, f"{data_id:04x} {row.get('DataName', '')}"):
        rows.append((data_id, row))
  return rows


def search_robs(query: str) -> list[tuple[int, dict[str, Any]]]:
  return [(code, row) for code, row in _robs_by_code().items()
          if _matches(query, f"{code:04x} {row.get('DataName', '')} {row.get('SystemName', '')}")]


def level49_key(seed: bytes) -> bytes:
  """Current GTS+ CCmdImgOpeDdr::CalculateKeyDataSecLv49 semantics."""
  if len(seed) != 6:
    raise RecorderError("TSS3 Image FFD level-49 seed must be six bytes")
  rotation_table = (1, 2, 3, 3, 2, 1)
  out = bytearray(6)
  for i, value in enumerate(seed):
    index = value & 7
    if index >= 6:
      index -= 6
    add = out[index] if index < i else seed[index]
    count = ((value >> rotation_table[i]) & 3) + 1
    rotated = ((value << count) | (value >> (8 - count))) & 0xFF
    out[i] = (rotated + add) & 0xFF
  return bytes(out)


def _expect_prefix(response: bytes, prefix: bytes, what: str) -> None:
  if not response.startswith(prefix):
    raise RecorderError(f"{what}: expected {prefix.hex().upper()} response, got {response.hex().upper()}")


def _be16_items(response: bytes, offset: int, what: str) -> list[int]:
  payload = response[offset:]
  if len(payload) % 2:
    raise RecorderError(f"{what}: odd trailing payload length {len(payload)}")
  return [int.from_bytes(payload[i:i + 2], "big") for i in range(0, len(payload), 2)]


def parse_operation_behaviors(response: bytes) -> list[int]:
  _expect_prefix(response, b"\xEB\x11", "Operation FFD behavior enumeration")
  return _be16_items(response, 2, "Operation FFD behavior enumeration")


def parse_operation_records(response: bytes, behavior: int) -> list[int]:
  _expect_prefix(response, b"\xEB\x12", "Operation FFD record enumeration")
  if len(response) < 4 or int.from_bytes(response[2:4], "big") != behavior:
    raise RecorderError(f"Operation FFD record enumeration: behavior echo mismatch for 0x{behavior:04X}")
  return sorted(set(_be16_items(response, 4, "Operation FFD record enumeration")))


def _parse_operation_blocks(payload: bytes, count: int | None) -> list[dict[str, Any]]:
  blocks = []
  offset = 0
  while offset < len(payload) and (count is None or len(blocks) < count):
    if len(payload) - offset < 3:
      raise RecorderError(f"Operation FFD record: truncated block header at byte {offset}")
    data_id = int.from_bytes(payload[offset:offset + 2], "big")
    length = payload[offset + 2]
    data_start = offset + 3
    data_end = data_start + length
    if data_end > len(payload):
      raise RecorderError(f"Operation FFD record: DID 0x{data_id:04X} length {length} exceeds response")
    blocks.append({"data_id": data_id, "length": length, "data": payload[data_start:data_end]})
    offset = data_end
  if count is not None and len(blocks) != count:
    raise RecorderError(f"Operation FFD record: expected {count} blocks, parsed {len(blocks)}")
  if offset != len(payload):
    raise RecorderError(f"Operation FFD record: {len(payload) - offset} trailing byte(s)")
  return blocks


def parse_operation_record(response: bytes, behavior: int, record: int) -> dict[str, Any]:
  _expect_prefix(response, b"\xEB\x13", "Operation FFD record")
  if len(response) < 6:
    raise RecorderError("Operation FFD record: truncated response header")
  got_behavior = int.from_bytes(response[2:4], "big")
  got_record = int.from_bytes(response[4:6], "big")
  if (got_behavior, got_record) != (behavior, record):
    raise RecorderError(
      f"Operation FFD record: echo mismatch, expected 0x{behavior:04X}/0x{record:04X}, "
      + f"got 0x{got_behavior:04X}/0x{got_record:04X}")

  # Live Camry EB13 responses carry a one-byte block count at offset 6.  The
  # recovered host parser also permits the count-less form, so retain that as a
  # strict fallback rather than making a guessed count mandatory.
  payload = response[6:]
  blocks: list[dict[str, Any]]
  count: int | None = None
  if payload:
    candidate = payload[0]
    try:
      blocks = _parse_operation_blocks(payload[1:], candidate)
      count = candidate
    except RecorderError:
      blocks = _parse_operation_blocks(payload, None)
  else:
    blocks = []

  seen: set[int] = set()
  deduped = []
  for block in blocks:
    if block["data_id"] in seen:
      continue
    seen.add(block["data_id"])
    deduped.append(block)
  return {"behavior": behavior, "record": record, "block_count": count, "blocks": deduped}


def parse_image_robs(response: bytes) -> list[int]:
  _expect_prefix(response, b"\xEB\x31", "Image FFD RoB enumeration")
  return _be16_items(response, 2, "Image FFD RoB enumeration")


def parse_image_record(response: bytes, rob: int, frame: int) -> dict[str, Any]:
  _expect_prefix(response, b"\xEB\x33", "Image FFD record")
  if len(response) < 9:
    raise RecorderError("Image FFD record: truncated response header")
  got_rob = int.from_bytes(response[2:4], "big")
  got_frame = int.from_bytes(response[4:8], "big")
  if (got_rob, got_frame) != (rob, frame):
    raise RecorderError(
      f"Image FFD record: echo mismatch, expected 0x{rob:04X}/0x{frame:08X}, "
      + f"got 0x{got_rob:04X}/0x{got_frame:08X}")
  declared_count = response[8]
  payload = response[9:]
  blocks = []
  offset = 0
  while offset < len(payload) and (declared_count == 0 or len(blocks) < declared_count):
    if len(payload) - offset < 3:
      raise RecorderError(f"Image FFD record: truncated block header at byte {offset + 9}")
    data_id = int.from_bytes(payload[offset:offset + 2], "big")
    offset += 2
    if 0x6000 <= data_id <= 0x6FFF:
      if len(payload) - offset < 4:
        raise RecorderError(f"Image FFD record: truncated BE32 length for DID 0x{data_id:04X}")
      length = int.from_bytes(payload[offset:offset + 4], "big")
      offset += 4
    else:
      length = payload[offset]
      offset += 1
    if len(payload) - offset < length:
      raise RecorderError(f"Image FFD record: DID 0x{data_id:04X} length {length} exceeds response")
    data = payload[offset:offset + length]
    offset += length
    blocks.append({"data_id": data_id, "length": length, "data": data})
  if declared_count and len(blocks) != declared_count:
    raise RecorderError(f"Image FFD record: expected {declared_count} blocks, parsed {len(blocks)}")
  if offset != len(payload):
    raise RecorderError(f"Image FFD record: {len(payload) - offset} trailing byte(s)")
  return {"rob": rob, "frame": frame, "block_count": declared_count or len(blocks), "blocks": blocks}


def image_frame_occurrence(split: int, data_set: int, trigger: int) -> int:
  return (split * 0x200 + data_set * 10 + trigger - 10) & 0xFFFFFFFF


def _extract_integer(data: bytes, row: dict[str, Any]) -> int:
  bit_length = int(row["BitLength"])
  byte_position = int(row["BytePosition"])
  bit_position = int(row["BitPosition"])
  start = (byte_position - 1) * 8 + (7 - bit_position)
  end = start + bit_length
  if bit_length <= 0 or byte_position <= 0 or bit_position not in range(8) or end > len(data) * 8:
    raise RecorderError(
      f"recorder DID 0x{int(row['DataID'], 16):04X} field {row['DataName']!r} exceeds {len(data)}-byte payload")
  value = int.from_bytes(data, "big")
  shift = len(data) * 8 - end
  raw = (value >> shift) & ((1 << bit_length) - 1)
  if row["Type"] == "s" and raw & (1 << (bit_length - 1)):
    raw -= 1 << bit_length
  return raw


def decode_signal(data: bytes, row: dict[str, Any]) -> dict[str, Any]:
  typ = row["Type"]
  bit_length = int(row["BitLength"])
  raw_int = _extract_integer(data, row)
  if typ == "f":
    if bit_length != 32:
      raise RecorderError(f"unsupported float width {bit_length}")
    raw: int | float = struct.unpack(">f", (raw_int & 0xFFFFFFFF).to_bytes(4, "big"))[0]
  elif typ == "d":
    if bit_length != 64:
      raise RecorderError(f"unsupported double width {bit_length}")
    raw = struct.unpack(">d", (raw_int & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big"))[0]
  else:
    raw = raw_int
  value = raw * float(row["Lsb"]) + float(row["Offset"])
  point = int(row["Point"])
  return {
    "name": row["DataName"], "raw": raw, "value": value,
    "formatted": f"{value:.{point}f}", "type": typ,
    "byte_position": int(row["BytePosition"]), "bit_position": int(row["BitPosition"]),
    "bit_length": bit_length,
  }


def decode_block(block: dict[str, Any]) -> dict[str, Any]:
  data_id = int(block["data_id"])
  data = bytes(block["data"])
  decoded = []
  errors = []
  for row in signal_rows(data_id):
    try:
      decoded.append(decode_signal(data, row))
    except RecorderError as e:
      errors.append(str(e))
  return {
    "data_id": data_id,
    "length": len(data),
    "data_hex": data.hex(),
    "signals": decoded,
    "decode_errors": errors,
  }


def decode_operation_record(record: dict[str, Any]) -> dict[str, Any]:
  return {
    "behavior": record["behavior"],
    "record": record["record"],
    "block_count": record["block_count"],
    "blocks": [decode_block(block) for block in record["blocks"]],
  }
