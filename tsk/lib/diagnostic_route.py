#!/usr/bin/env python3
"""Raw UDS route discovery helpers.

The known Toyota ``0x7A1 -> 0x7A9`` route is a useful first hypothesis, not a
response filter. These helpers send to a candidate request address and accept a
matching ISO-TP response on any non-echo arbitration ID and any observed bus.
"""
import time

DIAGNOSTIC_ADDRESS_RANGE = range(0x700, 0x800)


def parse_first_isotp(data: bytes) -> bytes | None:
  if not data:
    return None
  pci = data[0] >> 4
  if pci == 0x0:
    size = data[0] & 0x0F
    return bytes(data[1:1 + size])
  if pci == 0x1:
    return bytes(data[2:])
  return None


def matches_uds_response(body: bytes, request_sid: int) -> bool:
  if not body:
    return False
  if body[0] == 0x7F:
    return len(body) >= 2 and body[1] == request_sid
  return body[0] == ((request_sid + 0x40) & 0xFF)


def probe_response_route(panda, tx: int, bus: int, payload: bytes,
                         timeout: float = 0.3) -> dict | None:
  """Return the first matching ``{tx, rx, tx_bus, rx_bus, body, ms}`` route."""
  from opendbc.car.isotp import isotp_send

  try:
    panda.can_recv()
  except Exception:
    pass
  started = time.monotonic()
  try:
    isotp_send(panda, payload, tx, bus=bus)
  except Exception:
    return None

  deadline = started + timeout
  while time.monotonic() < deadline:
    try:
      frames = panda.can_recv()
    except Exception:
      return None
    for addr, *_rest, data, rx_bus in frames:
      if rx_bus >= 0x80:
        continue
      body = parse_first_isotp(bytes(data))
      if body is None or not matches_uds_response(body, payload[0]):
        continue
      return {
        "tx": int(tx),
        "rx": int(addr),
        "tx_bus": int(bus),
        "rx_bus": int(rx_bus),
        "body": body.hex(),
        "ms": int((time.monotonic() - started) * 1000),
      }
    time.sleep(0.001)
  return None


def discover_known_route(panda, tx: int, buses, payload: bytes = b"\x10\x01",
                         timeout: float = 0.3) -> dict | None:
  """Try a known request address on every candidate bus without assuming its RX ID."""
  for bus in buses:
    route = probe_response_route(panda, tx, bus, payload, timeout)
    if route is not None:
      route["source"] = "prior_address_hypothesis"
      return route
  return None


def read_f181(panda, route: dict, timeout: float = 0.2) -> bytes:
  """Read the full F181 value on a same-bus route using openpilot's ISO-TP client."""
  if route["tx_bus"] != route["rx_bus"]:
    return b""
  try:
    from opendbc.car.uds import UdsClient
    client = UdsClient(panda, route["tx"], route["rx"], route["tx_bus"],
                       timeout=timeout, response_pending_timeout=timeout)
    return bytes(client.read_data_by_identifier(0xF181))
  except Exception:
    return b""


def discover_eps_route(panda, buses, preferred_tx: int = 0x7A1,
                       addresses=None, preferred_timeout: float = 0.3,
                       scan_timeout: float = 0.05) -> dict | None:
  """Try the prior EPS address first, then scan and identify a Toyota 8965 responder.

  The fallback keeps the first diagnostic responder but prefers one whose F181 first
  frame contains ``8965``. Response IDs and response buses are always observed rather
  than inferred from the request address.
  """
  addresses = DIAGNOSTIC_ADDRESS_RANGE if addresses is None else addresses
  preferred = discover_known_route(panda, preferred_tx, buses, timeout=preferred_timeout)
  if preferred is not None:
    return preferred

  fallback = None
  for tx in addresses:
    if tx == 0x7DF:
      continue
    for bus in buses:
      route = probe_response_route(panda, tx, bus, b"\x10\x01", scan_timeout)
      if route is None:
        continue
      route["source"] = "address_scan"
      if fallback is None:
        fallback = route
      identity = read_f181(panda, route, timeout=max(scan_timeout, 0.2))
      if not identity:
        continue
      route["identity"] = identity.hex()
      if b"8965" in identity:
        route["source"] = "address_scan_f181_8965"
        return route
  return fallback
