# Ephemeral runtime evidence packages

This directory contains only **inert canary** artifacts imported from the canonical
`ghidra_rh850_analysis` work. The steering bridge binary is intentionally not shipped in
TSK while the scheduler transition, heartbeat, and reset-to-stock behavior remain
unvalidated on isolated hardware.

Current built-in package provenance:

- source repository commit: `c0e8175` (`tooling: generalize ephemeral runtime targets`)
- target: `8965B4512000`
- CodeFlash SHA-256: `21140bbd65e530a9e518a3e84e20e5d85679675bc09cc724cb177bb7c76bafde`
- target manifest SHA-256: `562393d0e40ba8dce158131860e2a2f3f97022cf480ee841247adacfa981b134`
- inert canary SHA-256: `81176c6e1c33451cfa63bd3b4a0e07b8b0fb952c70b3d67442f1a294ed6b651e`
- inert canary size: 332 bytes

Foreign target packages are generated offline by the semantic resolver in the analysis
repository and imported into TSK. Importing a package is evidence handling only; it does
not authorize live execution unless TSK also has target-specific evidence for the
post-auth code-substitution primitive and a target-accepted bootstrap fixture.
