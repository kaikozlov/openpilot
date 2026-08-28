"""No-hardware doubles for Toyota diagnostic CLI tests."""
from __future__ import annotations

from opendbc.car.uds import MessageTimeoutError, NegativeResponseError

CAMRY_ECUS = [
  ("Engine", 0x700), ("ECT", 0x701), ("Motor Generator", 0x724), ("Hybrid Control", 0x7D2),
  ("HV Battery", 0x747), ("Plug-in Control", 0x745), ("ECU 0x707", 0x707), ("ECU 0x703", 0x703),
  ("Power Steering", 0x7A1), ("Brake/EPB", 0x7B0), ("ECU 0x750", 0x750), ("ECU 0x7B3", 0x7B3),
  ("Air Conditioner", 0x7C4), ("ECU 0x7D1", 0x7D1), ("ECU 0x7D0", 0x7D0),
  ("Front Recognition Camera", 0x792), ("ECU 0x7A2", 0x7A2),
]
LEGISLATED_RESPONDERS = [0x7E8, 0x7EA, 0x7EB, 0x7ED, 0x7EE]
EXPECTED_EPS_F181 = b"8965F3307000"


def dtc_payload(*records: tuple[bytes, int], availability: int = 0xFF) -> bytes:
  data = bytes([availability])
  for number, status in records:
    data += number + bytes([status])
  return data


class FakePanda:
  def __init__(self, recv_batches=()):
    self.sent = []
    self.cleared = []
    self.safety = []
    self._batches = list(recv_batches)

  def can_send(self, address, data, bus, timeout=None):
    self.sent.append((address, bytes(data), bus))

  def can_recv(self):
    return self._batches.pop(0) if self._batches else []

  def can_clear(self, flags):
    self.cleared.append(flags)

  def set_safety_mode(self, mode, param=0):
    self.safety.append((mode, param))


class _ScriptedClient:
  def __init__(self, owner, address):
    self.owner = owner
    self.address = address

  def read_dtc_information(self, report_type, status_mask, *args, **kwargs):
    self.owner.calls.append((self.address, "read_dtc", report_type, status_mask))
    return self.owner.result(self.owner.dtc.get(self.address), MessageTimeoutError())

  def clear_diagnostic_information(self, group):
    self.owner.calls.append((self.address, "clear", group))
    return self.owner.result(self.owner.clear.get(self.address), None)

  def read_data_by_identifier(self, did):
    self.owner.calls.append((self.address, "read_did", did))
    return self.owner.result(self.owner.did.get(self.address, {}).get(did), MessageTimeoutError())


class ScriptedUds:
  def __init__(self):
    self.calls = []
    self.dtc = {}
    self.clear = {}
    self.did = {}

  @staticmethod
  def result(script, default):
    if callable(script) and not isinstance(script, Exception):
      script = script()
    if script is None:
      if isinstance(default, Exception):
        raise default
      return default
    if isinstance(script, Exception):
      raise script
    return script

  def factory(self, address):
    return _ScriptedClient(self, address)

  @staticmethod
  def negative_response():
    return NegativeResponseError("service not supported", 0x14, 0x11)
