"""Pure decoders for GTS-derived Toyota diagnostic signal metadata."""
from __future__ import annotations

from typing import Any

P5_LINEAR_MSB0_V1 = "p5-linear-msb0-v1"


class DecodeError(ValueError):
  pass


def extract_msb0(payload: bytes, bit_start: int, bit_end: int) -> int:
  """Extract an inclusive Toyota Data Monitor field with MSB-first bit numbering."""
  if bit_start < 0 or bit_end < bit_start:
    raise DecodeError(f"invalid bit range {bit_start}..{bit_end}")
  if bit_end >= len(payload) * 8:
    raise DecodeError(f"bits {bit_start}..{bit_end} exceed {len(payload)}-byte DID payload")
  start_byte = bit_start >> 3
  end_byte = bit_end >> 3
  assembled = int.from_bytes(payload[start_byte:end_byte + 1], "big")
  shift = 7 - (bit_end & 7)
  width = bit_end - bit_start + 1
  return (assembled >> shift) & ((1 << width) - 1)


def _trunc_div_toward_zero(numerator: int, denominator: int) -> int:
  if denominator == 0:
    raise DecodeError("Toyota physical conversion divisor is zero")
  quotient = abs(numerator) // abs(denominator)
  return -quotient if (numerator < 0) != (denominator < 0) else quotient


def convert_p5_physical(raw: int, *, bit_width: int, signed: bool, mul: int, div: int, offset: int) -> int:
  if bit_width <= 0:
    raise DecodeError(f"invalid bit width {bit_width}")
  mask = (1 << bit_width) - 1
  value = raw & mask
  if signed and value & (1 << (bit_width - 1)):
    value -= 1 << bit_width
  numerator = value * mul
  converted = numerator if div <= 1 else _trunc_div_toward_zero(numerator, div)
  return converted + offset


def format_p5_decimal(converted_integer: int, decimal_point_count: int) -> str:
  if decimal_point_count < 0:
    raise DecodeError(f"invalid decimal point count {decimal_point_count}")
  if decimal_point_count == 0:
    return str(converted_integer)
  scale = 10 ** decimal_point_count
  magnitude = abs(converted_integer)
  whole, fraction = divmod(magnitude, scale)
  sign = "-" if converted_integer < 0 else ""
  return f"{sign}{whole}.{fraction:0{decimal_point_count}d}"


def decode_signal(payload: bytes, row: dict[str, Any]) -> dict[str, Any]:
  decoder = row.get("decoder")
  if decoder != P5_LINEAR_MSB0_V1:
    raise DecodeError(f"unsupported decoder {decoder!r}")

  try:
    bit_start = int(row["bit_start"])
    bit_end = int(row["bit_end"])
    mul = int(row["mul"])
    div = int(row["div"])
    offset = int(row["offset"])
    decimal_point_count = int(row["decimal_point_count"])
  except (KeyError, TypeError, ValueError) as e:
    raise DecodeError(f"incomplete {P5_LINEAR_MSB0_V1} metadata") from e

  raw = extract_msb0(payload, bit_start, bit_end)
  converted = convert_p5_physical(
    raw,
    bit_width=bit_end - bit_start + 1,
    signed=bool(row.get("signed", False)),
    mul=mul,
    div=div,
    offset=offset,
  )
  patterns = row.get("patterns") or {}
  pattern = patterns.get(str(converted))
  return {
    "raw": raw,
    "converted_integer": converted,
    "value": format_p5_decimal(converted, decimal_point_count),
    "pattern": pattern,
  }


def format_decoded_signal(payload: bytes, row: dict[str, Any]) -> str:
  result = decode_signal(payload, row)
  name = str(row.get("name") or "(unnamed)")
  width = int(row["bit_end"]) - int(row["bit_start"]) + 1
  raw_digits = max(1, (width + 3) // 4)
  raw_text = f"0x{result['raw']:0{raw_digits}X}"
  if result["pattern"] is not None:
    rendered = str(result["pattern"])
  else:
    rendered = str(result["value"])
    unit = row.get("unit")
    if unit:
      rendered += f" {unit}"
  return f"{name}: {rendered} (raw={raw_text})"
