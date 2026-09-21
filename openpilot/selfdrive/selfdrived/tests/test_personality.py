from openpilot.cereal import log
from openpilot.selfdrive.selfdrived.selfdrived import personality_for_follow_distance_bars


def test_personality_for_follow_distance_bars():
  assert personality_for_follow_distance_bars(1) == log.LongitudinalPersonality.aggressive
  assert personality_for_follow_distance_bars(2) == log.LongitudinalPersonality.standard
  assert personality_for_follow_distance_bars(3) == log.LongitudinalPersonality.standard
  assert personality_for_follow_distance_bars(4) == log.LongitudinalPersonality.relaxed
