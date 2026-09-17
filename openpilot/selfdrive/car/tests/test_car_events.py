import unittest

from opendbc.car.structs import car
from opendbc.car.toyota.values import CAR
from openpilot.selfdrive.car.car_events import CarEvents, EventName


def non_adaptive_cruise_state() -> car.CarState:
  state = car.CarState(gearShifter=car.CarState.GearShifter.drive)
  state.cruiseState.available = True
  state.cruiseState.nonAdaptive = True
  return state


class TestCarEvents(unittest.TestCase):
  def test_camry_tss3_allows_non_adaptive_cruise_for_lateral(self):
    cp = car.CarParams(carFingerprint=CAR.TOYOTA_CAMRY_TSS3, brand="toyota")
    state = non_adaptive_cruise_state()

    events = CarEvents(cp).create_common_events(state, state)

    self.assertNotIn(EventName.wrongCruiseMode, events.names)

  def test_non_adaptive_cruise_still_blocks_other_toyotas(self):
    cp = car.CarParams(carFingerprint=CAR.TOYOTA_COROLLA_TSS3, brand="toyota")
    state = non_adaptive_cruise_state()

    events = CarEvents(cp).create_common_events(state, state)

    self.assertIn(EventName.wrongCruiseMode, events.names)


if __name__ == "__main__":
  unittest.main()
