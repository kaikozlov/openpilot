# Target-specific openpilot integration gate

TSK deliberately does not turn a recovered SecOC key into a guessed Toyota platform.
The target must first be observed, then implemented in the checked-out `opendbc_repo`,
then verified stationary/bench-side before TSK permits operational `SecOCKey`
installation.

## Why this gate exists

Toyota platform selection controls more than the MAC key. In the current opendbc Toyota
stack it determines, directly or indirectly:

- powertrain/SecOC DBC selection;
- `ToyotaFlags.SECOC` and `secOcRequired`;
- the low-byte EPS scaling encoded in Toyota `safetyParam`;
- `ToyotaSafetyFlags.SECOC`, `LTA`, `STOCK_LONGITUDINAL`, and where applicable
  `ALT_BRAKE`;
- torque versus angle steering (`ToyotaFlags.ANGLE_CONTROL`);
- steering fault/status interpretation;
- camera/default versus radar/alpha-long longitudinal ownership;
- which secured command paths are emitted by `CarController`.

A key that happens to authenticate `0x131`/`0x2E4` therefore cannot prove that a target
should reuse Sienna/RAV4/Yaris platform metadata.

## Current sender contract

The current Toyota SecOC controller has three classic protected command paths:

- `STEERING_LKA` / `0x2E4` for LKA torque control;
- `STEERING_LTA_2` / `0x131` for the secured LTA control domain;
- `ACC_CONTROL_2` / `0x183` when openpilot longitudinal is active.

TSK reports compatibility with those paths, but they are not the target-discovery filter.
Unknown classic protected IDs can be surfaced structurally from the full READY capture and
then proven by AES-CMAC.

The newer firmware analysis does **not** justify expanding that sender contract just
because more protected receive records are now understood. On Sienna `8965B4512000`,
`0x132` is a firmware-verified classic protected RX profile with a bounded snapshot-only
downstream role, while CAN-FD `0x090` and `0x0D7` are protected sensor/status inputs
(rear-wheel/steering-angle-speed and vehicle-speed/validity domains respectively). TSK now
cryptographically verifies all three when observed, but openpilot must not synthesize them
as new control outputs. Likewise, `0x131` is statically confirmed as the second steering
command mode, but that alone does not satisfy the existing dynamic/safety requirement for
LTA angle actuation.

## Recovery geometry is not inferred from target identity or handoff

The recovery side now has an equally strict calibration boundary. A successful
application -> bootloader PROGRAMMING handoff proves only that the endpoint transitioned;
it does not prove the authenticated RequestDownload base/size, routine-`0x10F0`
verification geometry, or callback address embedded in a payload package.

`tsk/lib/ram_exec_geometry.py` therefore resolves authenticated RAM execution by exact
F181. The current trusted `FEBF0000 + 0x1000`, callback-`FEBF0000` contract is limited to
`8965B4209000`, `8965B4233100`, `8965B4509100`, and independently analyzed
`8965B4512000`. Unknown F181s remain blocked after a successful programming probe until
that complete contract is evidenced. The externally observed newer-Toyota shellcode VMA
`FEBE0000` is explicitly **not** treated as a RequestDownload/callback geometry.

This recovery gate and the openpilot integration manifest are independent: proving RAM
execution does not select a DBC/safety/control profile, and proving a target's openpilot
profile does not authorize a Sienna-derived payload geometry.

## Manifest required before implementation

`/target-profile.html` records these fields and an evidence source for every one:

| field | required meaning |
|---|---|
| `platform_name` | exact opendbc `CAR` member to implement |
| `dbc_pt` | exact Toyota PT/SecOC DBC name |
| `safety_flags` | intended complete Toyota `safetyParam`, decimal or `0x` integer |
| `steer_control_type` | canonical `torque` or `angle` |
| `eps_scale` | exact integer EPS scale |
| `lateral_command_role` | target command ID(s), bus, framing, request/command meaning |
| `lateral_status_feedback` | target EPS/status feedback that proves acceptance/fault state |
| `longitudinal_control` | `openpilot_default`, `stock_default`, or `openpilot_alpha` |
| `longitudinal_topology` | evidence for camera/radar ownership, protected IDs and disable/block route |

The descriptive fields still matter even where opendbc cannot machine-check them; they are
the evidence used to review the eventual patch and stationary probe.

## Machine source audit

`tsk.lib.opendbc_integration_audit` reads the checked-out `opendbc_repo` without importing
or executing it. A reviewed manifest remains **not code-ready** unless all checks pass:

1. Toyota `values.py`, `fingerprints.py`, `interface.py`, and `carcontroller.py` are present.
2. `CAR.<platform_name>` is actually implemented.
3. The platform is SecOC-enabled (`ToyotaSecOCPlatformConfig` or explicit SecOC flag).
4. Its effective PT DBC equals the reviewed `dbc_pt`, and the DBC generator source exists.
5. `ANGLE_CONTROL` agrees exactly with reviewed `steer_control_type`.
6. `EPS_SCALE` resolves to the reviewed integer.
7. `RADAR_ACC`/default-long behavior agrees with `longitudinal_control`.
8. The source-derived Toyota `safetyParam` equals reviewed `safety_flags`.
9. `FW_VERSIONS[CAR.<platform>]` contains the exact target EPS F181.
10. The Toyota interface still contains the safety/longitudinal derivation contract.
11. The Toyota controller still contains secured LKA/LTA/ACC command paths.

The audit stores SHA-256 hashes of the reviewed Toyota source files and DBC generator in
the target profile. `Re-audit opendbc` on the target-profile page re-verifies the recovered
key against the current oracle and reruns the source checks after an opendbc patch/submodule
update.

As a sanity check during development, the audit resolves the existing
`TOYOTA_SIENNA_4TH_GEN` / F181 `8965B4509100` configuration as source-ready with
`toyota_secoc_pt_generated`, torque control, EPS scale `73`, default openpilot
longitudinal, and safetyParam `0x849`.

## What the eventual target patch must contain

Once the exact Camry/TSS3 evidence fills the manifest, the corresponding opendbc change is
expected to include, as justified by that evidence:

- a new/updated Toyota `CAR` platform config with correct specs and flags;
- exact EPS F181 and the other essential firmware fingerprints obtained from the target;
- a DBC that actually describes the target's parsed status and command messages;
- correct `EPS_SCALE` override if the target is not the default 73;
- `ANGLE_CONTROL` only if the target uses the LTA/angle command path for openpilot lateral;
- `RADAR_ACC`/longitudinal ownership matching the observed target topology;
- Toyota safety behavior/parameters consistent with the reviewed command mode and scale;
- parser/controller changes only where the target differs from the existing SecOC contract;
- tests covering the new platform/fingerprint/DBC and its control/safety assumptions.

TSK cannot truthfully write those values before the target supplies them. The absence of a
Camry/TSS3 platform in the current checkout is therefore an explicit blocked state rather
than a reason to alias the target to `TOYOTA_CAMRY_TSS2` or `TOYOTA_SIENNA_4TH_GEN`.

## Stationary gate after the code patch

Code-ready is still not operational-ready. The reviewed opendbc target must next produce a
profile-bound stationary/bench session artifact containing:

- independent evidence that vehicle speed stayed at or below `0.05 m/s`;
- a cryptographically verified **zero-actuation** command on a target-verified stream;
- target-specific EPS/status evidence showing the command was accepted;
- before/after evidence showing no new EPS fault latch;
- the raw session capture under `/cache/tsk`, whose SHA-256 is recorded in the result.

TSK's stationary verifier only validates this evidence. It intentionally does not invent
or transmit a target steering command before the target-specific DBC/controller semantics
exist.

Only after key recovery + reviewed manifest + opendbc source audit + stationary verification
does `/api/install-recovered-key` copy the recovered private key into the existing
`SecOCKey` interface used by openpilot.
