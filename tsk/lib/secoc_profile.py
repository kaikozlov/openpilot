#!/usr/bin/env python3
"""Cross-variant Toyota SecOC framing hypotheses and verified reference profiles.

These sets are capture/matcher inputs, not a claim that every Toyota target owns
every listed PDU. Cryptographic verification and the target profile remain the
trust boundary.
"""

SYNC_ADDR = 0x00F

# Classic 8-byte protected family. Most entries are pinned by opendbc sender
# profiles; 0x132 is added from the firmware-verified 8965B4512000 receive record
# (4 authentic payload bytes + 4-bit transmitted freshness + 28-bit CMAC).
CLASSIC_PROTECTED_ADDRS = frozenset({
  0x116,
  0x131,
  0x132,
  0x177,
  0x183,
  0x24D,
  0x283,
  0x2E4,
  0x344,
})

# The analyzed Sienna application has exactly six SecOC RX records. The three
# ordinary classic protected records are 0x2E4/0x131/0x132; 0x090/0x0D7 are
# 32-byte CAN-FD protected records. 0x00F is synchronization.
SIENNA_8965B4512000_CLASSIC_RX_ADDRS = frozenset({0x131, 0x132, 0x2E4})
SIENNA_8965B4512000_FD_RX_ADDRS = frozenset({0x090, 0x0D7})
FD_PROTECTED_ADDRS = SIENNA_8965B4512000_FD_RX_ADDRS

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

# Firmware-derived non-classic protected receive profiles. They stay out of the
# classic structural-candidate heuristic but are retained and cryptographically
# verified with their now-pinned 28-byte-payload framing when observed.
ADDITIONAL_PROTECTED_HYPOTHESES = FD_PROTECTED_ADDRS
CAPTURE_PROTECTED_HYPOTHESES = CLASSIC_PROTECTED_ADDRS | FD_PROTECTED_ADDRS
