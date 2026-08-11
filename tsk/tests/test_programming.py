import sys
import types
import unittest
from unittest.mock import Mock, patch

import tsk.lib.programming as programming


class _MessageTimeoutError(Exception):
  pass


class _InvalidServiceIdError(Exception):
  pass


class _NegativeResponseError(Exception):
  def __init__(self, error_code):
    super().__init__(f"NRC 0x{error_code:02x}")
    self.error_code = error_code


class _SessionType:
  DEFAULT = 0x01
  PROGRAMMING = 0x02
  EXTENDED_DIAGNOSTIC = 0x03


class _Client:
  def __init__(self, programming_result):
    self.programming_result = programming_result
    self.sessions = []

  def diagnostic_session_control(self, session):
    self.sessions.append(session)
    if session == _SessionType.PROGRAMMING and self.programming_result is not None:
      raise self.programming_result


def _uds_modules():
  opendbc = types.ModuleType("opendbc")
  car = types.ModuleType("opendbc.car")
  uds = types.ModuleType("opendbc.car.uds")
  uds.SESSION_TYPE = _SessionType
  uds.InvalidServiceIdError = _InvalidServiceIdError
  uds.MessageTimeoutError = _MessageTimeoutError
  uds.NegativeResponseError = _NegativeResponseError
  return {
    "opendbc": opendbc,
    "opendbc.car": car,
    "opendbc.car.uds": uds,
  }


class TestProgrammingHandoff(unittest.TestCase):
  def setUp(self):
    self.route = {
      "tx": 0x7A1,
      "rx": 0x7A9,
      "tx_bus": 1,
      "rx_bus": 1,
      "elm327_param": 1,
      "semantic_path": "normal-harness",
    }
    self.boot_route = dict(self.route)

  def test_timeout_is_success_when_endpoint_reappears_on_preserved_route(self):
    client = _Client(_MessageTimeoutError())
    rediscover = Mock(return_value=self.boot_route)
    health = Mock(side_effect=[{"phase": "before"}, {"phase": "after_request"}, {"phase": "after_reappear"}])

    with patch.dict(sys.modules, _uds_modules()), \
         patch.object(programming, "uds_client", return_value=client), \
         patch.object(programming, "rediscover_route", rediscover), \
         patch.object(programming, "panda_health_snapshot", health):
      route, telemetry = programming.enter_programming_bootloader(
        object(), self.route, prepare_sessions=True, reappearance_timeout=0.1,
      )

    self.assertEqual(route, self.boot_route)
    self.assertEqual(client.sessions, [_SessionType.DEFAULT, _SessionType.EXTENDED_DIAGNOSTIC,
                                       _SessionType.PROGRAMMING])
    self.assertTrue(telemetry["programming_response_timeout"])
    self.assertEqual(telemetry["route_before"]["elm327_param"], 1)
    self.assertEqual(telemetry["route_after"]["semantic_path"], "normal-harness")
    rediscover.assert_called_once_with(
      unittest.mock.ANY, self.route, buses=[1], preferred_timeout=0.35, scan_timeout=0.1,
    )

  def test_explicit_nrc_is_rejection(self):
    client = _Client(_NegativeResponseError(0x22))
    with patch.dict(sys.modules, _uds_modules()), \
         patch.object(programming, "uds_client", return_value=client), \
         patch.object(programming, "panda_health_snapshot", return_value={"bus": 1}), \
         patch.object(programming, "rediscover_route") as rediscover:
      with self.assertRaises(programming.ProgrammingHandoffError) as cm:
        programming.enter_programming_bootloader(object(), self.route, prepare_sessions=True)

    self.assertEqual(cm.exception.nrc, 0x22)
    self.assertEqual(cm.exception.telemetry["programming_nrc"], 0x22)
    rediscover.assert_not_called()


if __name__ == "__main__":
  unittest.main()
