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
# The current Toyota openpilot controller signs these two classic control streams with
# SecOCKey. A candidate verified only on another classic domain is valuable evidence but
# is not sufficient to install as the controller key.
OPENPILOT_CONTROL_PROTECTED_ADDRS = frozenset({0x131, 0x2E4})

ADDITIONAL_PROTECTED_HYPOTHESES = frozenset({0x090, 0x0D7, 0x132})
CAPTURE_PROTECTED_HYPOTHESES = CLASSIC_PROTECTED_ADDRS | ADDITIONAL_PROTECTED_HYPOTHESES
