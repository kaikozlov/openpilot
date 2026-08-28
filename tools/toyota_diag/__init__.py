"""Toyota/GTS-derived diagnostic tooling for Comma.

The bundled F33 registry is generated outside openpilot from the reverse-engineered
GTS+/Techstream corpus. Offline catalog/planning commands need no Panda. Live commands
require exclusive Panda ownership. The runtime core (session/executor/utility) executes
only registry rows graded `execution: "executable"`; every bundled v3 Active Test is
plan-only.
"""
