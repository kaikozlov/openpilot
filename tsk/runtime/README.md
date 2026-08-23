# Ephemeral runtime evidence packages

This directory contains the executable **inert canary** package for the exact Sienna target
plus resolver-produced, evidence-only foreign manifests imported from the canonical
`ghidra_rh850_analysis` work. The steering bridge binary is intentionally not shipped in
TSK while the scheduler transition, heartbeat, and reset-to-stock behavior remain
unvalidated on isolated hardware.

Current built-in package provenance:

- target manifest / audit provenance: `b1baa93` (`feat: add RAM command5 signing proxy`)
- inert canary binary remains the audited build from the earlier `c0e8175` runtime baseline
- target: `8965B4512000`
- CodeFlash SHA-256: `21140bbd65e530a9e518a3e84e20e5d85679675bc09cc724cb177bb7c76bafde`
- target manifest SHA-256: `e0fddd8204ec9ec34b6cdf88d3b34f24097cef9609d7471f50c181b8ef626395`
- inert canary SHA-256: `81176c6e1c33451cfa63bd3b4a0e07b8b0fb952c70b3d67442f1a294ed6b651e`
- inert canary size: 332 bytes

Bundled negative-capability regression manifests from the same resolver:

- `8965H1202000`: RE provenance `b1baa93`, manifest SHA-256 `d2f4d4bd1eff92ae801b5aae3fccfeb94cf0f402f41bf7eb32ae74ef48e9fa38`
- `8965F1208000`: RE provenance `969fab5`, manifest SHA-256 `432ccc6801b97e75f96a4fc7cd1e466e87c2064fd368bd298ad17ca8a8c95186`

Both resolve the foreign image semantically and bind its authenticated-RAM bootstrap
evidence, but both report `semantic-resolved-steering-unsupported`, unresolved image-bound
retained-RWX geometry, a three-record SecOC queue, and missing classic `0x2E4`/`0x131`
steering records. TSK treats these files as **evidence only**: they cannot satisfy the
canary-package validator and never expose bridge execution.

Host-side bootstrap request construction also mirrors the current RE route model for the
`old`/`new` UDS routine magic and CPU0/CPU1 memory-ID + DID-0203 conventions. Those builders
are plan/test primitives, not a foreign-target execution allowlist. The built-in B4512000
live canary intentionally preserves its already-reviewed five-zero-byte DID-0203 request
rather than inheriting the generalized CPU0 convention.

Future target packages are generated offline by the semantic resolver in the analysis
repository and imported into TSK. A complete executable package still requires the audited
canary plus exact image-bound RAM geometry. Package import never authorizes live execution
unless TSK also has target-specific evidence for the post-auth code-substitution primitive
and a target-accepted bootstrap fixture.
