#!/usr/bin/env python3
"""Cross-variant Toyota classic SecOC framing hypotheses.

These IDs are hypotheses for capture and offline verification, not a claim that a
particular ECU transmits or receives every one of them. The classic 8-byte sender
format is shared across the currently known Toyota SecOC profile family.
"""

SYNC_ADDR = 0x00F

# Pinned opendbc classic 8-byte SecOC family. The matcher evaluates each ID
# independently and only trusts a key after cryptographic validation.
CLASSIC_PROTECTED_ADDRS = frozenset({
  0x116,
  0x131,
  0x177,
  0x183,
  0x24D,
  0x283,
  0x2E4,
  0x344,
})

# Additional firmware-derived Sienna protected receive-profile IDs useful as
# annotations in passive capture. 0x090/0x0D7 are CAN-FD profiles and are not fed
# to the classic 8-byte verifier. 0x132 remains annotation-only here until its
# sender framing is independently pinned in the cross-variant tooling.
#
# These are *current openpilot implementation compatibility* sets, not the target
# discovery boundary. Toyota CarController currently signs 0x2E4 STEERING_LKA and
# 0x131 STEERING_LTA_2 for lateral control; with openpilot longitudinal enabled it
# additionally signs 0x183 ACC_CONTROL_2. Unknown/newer targets must be discovered
# from their own captures rather than forced to match these IDs.
CURRENT_OPENPILOT_LATERAL_PROTECTED_ADDRS = frozenset({0x131, 0x2E4})
CURRENT_OPENPILOT_LONGITUDINAL_PROTECTED_ADDRS = frozenset({0x183})
CURRENT_OPENPILOT_PROTECTED_ADDRS = (
  CURRENT_OPENPILOT_LATERAL_PROTECTED_ADDRS | CURRENT_OPENPILOT_LONGITUDINAL_PROTECTED_ADDRS
)

# Compatibility alias for older callers/tests. New workflow code should use the
# explicit lateral/longitudinal sets above and must not interpret this as a target
# profile definition.
OPENPILOT_CONTROL_PROTECTED_ADDRS = CURRENT_OPENPILOT_LATERAL_PROTECTED_ADDRS

ADDITIONAL_PROTECTED_HYPOTHESES = frozenset({0x090, 0x0D7, 0x132})
CAPTURE_PROTECTED_HYPOTHESES = CLASSIC_PROTECTED_ADDRS | ADDITIONAL_PROTECTED_HYPOTHESES
