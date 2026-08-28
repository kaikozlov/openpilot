"""No-hardware doubles for Toyota diagnostic CLI tests."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

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

  def diagnostic_session_control(self, session_type):
    self.owner.calls.append((self.address, "session", int(session_type)))
    return self.owner.result(self.owner.session.get((self.address, int(session_type))), None)

  def tester_present(self, *args, **kwargs):
    self.owner.calls.append((self.address, "tester_present"))
    return self.owner.result(self.owner.tester.get(self.address), None)

  def input_output_control_by_identifier(self, did, control_parameter_type,
                                         control_option_record=b"", control_enable_mask_record=b""):
    self.owner.calls.append((self.address, "io_control", int(did), int(control_parameter_type),
                             bytes(control_option_record), bytes(control_enable_mask_record)))
    return self.owner.result(self.owner.io_control.get((self.address, int(did), int(control_parameter_type))), b"")

  def routine_control(self, routine_control_type, routine_identifier, routine_option_record=b""):
    self.owner.calls.append((self.address, "routine", int(routine_control_type), int(routine_identifier),
                             bytes(routine_option_record)))
    return self.owner.result(
      self.owner.routine.get((self.address, int(routine_control_type), int(routine_identifier))), b"")




class ScriptedUds:
  def __init__(self):
    self.calls = []
    self.dtc = {}
    self.clear = {}
    self.did = {}
    self.session = {}
    self.tester = {}
    self.io_control = {}
    self.routine = {}


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


SYNTH_ECU_KEY = "ecu"
SYNTH_ECU_ADDRESS = 0x7A0
SYNTH_CATEGORY_ID = 9001


def build_registry_document(*, session_control=None, active_tests=None, utilities=None) -> dict:
  """A minimal loader-valid registry document for runtime-core tests."""
  catalog = {
    "category": {"name": "Synthetic"},
    "dids": {},
    "dtcs": {},
    "active_tests": list(active_tests or []),
  }
  if utilities is not None:
    catalog["utilities"] = list(utilities)
  profile = {
    "profile": "synthetic-test",
    "vehicle": "Synthetic Vehicle",
    "panda_bus": 0,
    "fault_status_mask": 0xAF,
    "ecus": [{"key": SYNTH_ECU_KEY, "name": "Synthetic ECU", "address": SYNTH_ECU_ADDRESS,
              "category_id": SYNTH_CATEGORY_ID}],
    "identity_guard": {"ecu": SYNTH_ECU_KEY, "did": 0xF181, "contains_ascii": "8965F3307000"},
    "dtc_clear": {"functional_obd": {"request_id": 0x7DF, "mode04_request": "0104000000000000",
                                     "expected_responders": [0x7E8]}},
  }
  if session_control is not None:
    profile["session_control"] = session_control
  return {"schema": "toyota-diagnostics-registry-v3", "profile": profile, "catalogs": {str(SYNTH_CATEGORY_ID): catalog}}


def write_registry(document, tmp_path):
  path = tmp_path / "synthetic_registry.json"
  path.write_text(json.dumps(document))
  return path


def load_profile(tmp_path=None, **document_kwargs):
  from tools.toyota_diag import registry
  if tmp_path is None:
    with tempfile.TemporaryDirectory() as directory:
      return registry.load_registry(write_registry(build_registry_document(**document_kwargs), Path(directory)))
  return registry.load_registry(write_registry(build_registry_document(**document_kwargs), tmp_path))


def synthetic_ecu(profile):
  return profile.lookup_ecu(SYNTH_ECU_KEY)


def guard_pass(scripted, address=SYNTH_ECU_ADDRESS):
  scripted.did.setdefault(address, {})[0xF181] = EXPECTED_EPS_F181
