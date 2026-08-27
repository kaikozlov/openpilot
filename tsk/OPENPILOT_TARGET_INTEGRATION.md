# Target-specific openpilot integration gate

TSK deliberately does not turn a recovered SecOC key into a guessed Toyota platform.
The target must first be observed, then implemented in the checked-out `opendbc_repo`,
then verified stationary/bench-side before TSK permits operational `SecOCKey`
installation.

## 2026-08-26 Camry/F33 reverse-engineering sync status

This fork is synchronized to the exact maintainer 2026 Camry/F33 evidence through
`ghidra_rh850_analysis` VAR-051..VAR-058 plus the current application-runtime placement
closure. The durable target summary is [`CAMRY_2026_FINDINGS.md`](CAMRY_2026_FINDINGS.md).
Corolla H/F remains useful prior art, but the Camry port no longer depends on transferring
Corolla addresses or guessing a platform from family similarity.

The passive Camry port entered the root at baseline commit
`d7d7dfd7e49961e9d35eb7a7681e8756ceee8d04`; the checked-out opendbc now includes the
exact F33 fault-state observer at
`0d5773bd393bbf3d4109728171d2390b60fcde16`. The exact target is
`TOYOTA_CAMRY_TSS3`, bound to EPS F181 `8965F3307000 / 8A3113303100`. It remains
an evidence-acquisition checkpoint, not production steering authorization.

The status vocabulary below is deliberate: **implemented** means the code path is present;
**implemented-read-only** means only evidence acquisition/inspection is exposed;
**prepared-but-hardware-gated** means host-side code or transport scaffolding exists but
cannot be promoted operationally without the named live proof; **intentionally-not-applicable**
means current firmware evidence disproves that transfer for the named target; and
**blocked-by-live-policy** means the target-native static contract is sufficiently recovered
but production behavior still requires live authority/safety evidence; and **not-yet-implementable**
means no correct implementation primitive has yet been recovered.

| RE result / capability | status | OpenPilot/TSK implementation boundary |
|---|---|---|
| exact F33 identity / route | **implemented-read-only** | EPS `0x7A1->0x7A9`, FRC `0x792->0x79A`, Brake `0x7B0->0x7B8`, all on normal-harness `(bus1,param1)`, are retained in `tsk.lib.camry_f33`; no family-prefix matching |
| exact F33 CodeFlash acquisition | **implemented** | `tsk/lib/dump_codeflash.py` and `tsk/tools/dump_codeflash.py` exact-gate F181, route, NRTD Ready=0, payload SHA and boot geometry; the proven 2 MiB range-reader fixture is bundled and partial coverage is resumable |
| F33 authenticated-RAM bootstrap | **implemented** | exact target proved old-stack boot SA, zero `0203/0201/0202`, `FEBF0000+0x1000`, `0x10F0 45 00`, and `0xFF00`; this does not imply application retention |
| F33 DataFlash / RAM recovery | **implemented-read-only** | exact DataFlash/LocalRAM/GlobalRAM evidence is retained; CPU-visible SecOC key search is negative, consistent with active ICU-S slot 4; no key is fabricated from the negative |
| F33 Ready / full gear state | **implemented-read-only** | source-real `0x51E B0[7]` NRTD/READY and `0x127` `P/R/N/D/B = 0/1/2/3/4` are parsed and replay-tested |
| F33 cruise switch observation | **implemented-read-only** | FRC P5 DIDs and bus-1 `0x0FE/32` MAIN/RES+/SET-/CANCEL carrier are retained; following-distance `0x251/0x5AF` joins remain candidates |
| F33 protected B6 receiver / SecOC geometry | **implemented-read-only** | exact PDU44, 28-byte application + FV4/CMAC28, FV46/CMAC128, slot4/command7, Target Lateral ID, signed target angle, sequence, companion fields and exact target limits/timing are represented in opendbc helpers/DBC |
| F33 passive platform / DBC / CarState | **implemented-read-only** | `TOYOTA_CAMRY_TSS3` has exact F181 binding, generated TSS3 DBC, source-real Ready/gear replay, state parsing, explicit B6 packing/freshness/signing interfaces and shadow safety. CarParams remains `dashcamOnly` / `SafetyModel.noOutput`; controller emits zero CAN |
| F33 generated Tx/status + `0x394` classifier | **implemented-read-only** | exact `0x030/0x351/0x394/0x4A3/0x4C8` Tx/packer geometry is retained and the 17-row `0x394` table projection is decoded to candidate internal states; lossy tuples stay candidate sets and are deliberately not converted to openpilot temporary/permanent faults |
| F33 production B6 sender / safety | **blocked-by-live-policy** | receiver limits/timing are closed, but stock B6 cadence/full 28-byte template/freshness, exclusive relay suppression, ICU-S generation permission/latency, driver override/current response and live fault/recovery dynamics remain mandatory |
| F33 application-retained RAM placement | **implemented-read-only** | low `FEBF0000` boot pocket is disproved as application-retained; live high tail `FEBFF9F0..FEBFFBFB` (524 bytes) survives stock startup and is executable |
| F33 application XCP byte placement | **prepared-but-hardware-gated** | exact firmware exposes `0x7F7/0x7F8` XCP callbacks and writable `FEBF7C00..FEBFFBFF`; normal `(bus1,param1)` CONNECT timed out, so physical/session reachability remains open |
| F33 application-mode volatile control transfer | **not-yet-implementable** | 312 computed-call sites plus fixed-DMAC census recovered no concrete reversible application callback/PC object in the writable high tail. TSK does not guess an execution pivot |
| F33 RID `0x100F` command-5 path | **implemented-read-only** | target-native path reaches command 5 but uses fixed private 16-byte input/result; it is an oracle, not a general 7-/36-byte SecOC signer API |
| H/F classic Sienna steering bridge | **intentionally-not-applicable** | H/F and F33 TSS3 steer through protected FD B6 rather than classic `0x2E4/0x131`; the old Sienna resident bridge is not projected onto these targets |
| persistent Gate-2 patching | **intentionally-not-applicable** to preferred production path | patch/restore evidence remains RE-side; preferred architecture remains reset-to-stock volatile execution |

### Passive Camry TSS3 checkpoint

The exact Camry implementation deliberately separates **observability** from **control**:

- `ToyotaFlags.TSS3` and `ToyotaFlags.SECOC` are both set without inheriting TSS2.
- `TSS3_EXACT_FW_VERSIONS` binds the exact EPS F181 and corroborating FRC/Brake identities
  without polluting production `FW_VERSIONS` with an incomplete research ECU inventory.
- `toyota_tss3_pt_generated` includes only target-evidenced state/status and B6 fields.
  B6 construction/signing helpers exist for deterministic shadow work; no sender is enabled.
- CarState consumes source-real steering angle/rate, wheel speed, brake/gas, `0x030` physical
  driver torque, full P/R/N/D/B, and Ready. Internal `0x394` states are candidate-decoded
  without inventing temporary/permanent fault policy.
- the 179-ID Camry CAN census is intentionally excluded from legacy fingerprinting because
  the Corolla TSS3 census is a strict subset; platform selection is exact-F181-bound.
- `CarParams.dashcamOnly=True`, Panda uses `SafetyModel.noOutput`, longitudinal control is
  disabled, and `CarController.update()` sends **no CAN messages**.

Exact firmware now closes the receiver-side command envelope: Target Lateral ID 11 selects
LTA/LCA mode2; signed B4:B5 target angle uses `1024/17870 deg/count`; absolute envelope is
±1745 raw; delta is 78 raw per effective modulo-64 gap with cap 8; foreground is 5 ms and
the seven-tick receive deadline is nominally 35 ms. These constraints are shadow-safety
inputs only. They do not substitute for stock sender, driver override, current response,
relay authority, signer permission/latency or live fault/recovery evidence.

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

For H/F Corolla and exact F33 Camry, the TSS3 DBC models the protected FD `0x0B6`
receiver fields recovered from each target. F33 independently closes PDU44, Target Lateral
ID, signed target steering angle, modulo-64 sequence, FV46/FV4/CMAC28 and receiver limits.
This is intentionally **not** an enabled sender contract. The TSS3 controller exits before
all existing Toyota sender logic and emits no CAN traffic until the stock-B6
sender/authentication/suppression/safety contract is closed.

## Recovery compatibility is split into independent evidence gates

The recovery side uses the same evidence discipline as target integration. A successful
application -> bootloader PROGRAMMING handoff proves only that the endpoint transitioned;
it does not prove an encrypted payload or application-resident runtime is portable.

TSK therefore separates three contracts:

1. **authenticated-RAM bootstrap / boot geometry** — exact-F181 evidence for the shared
   boot SecurityAccess family, `0203→0201→0202`, `FEBF0000 + 0x1000`, `0x10F0`, and
   `0xFF00` callback route;
2. **exact encrypted fixture acceptance** — the selected 4 KiB ciphertext must be
   independently evidenced for that F181; and
3. **application-retained ephemeral runtime** — an exact 1 MiB CodeFlash SHA must resolve
   the callback-free startup/scheduler/SecOC/COM contract and retained application R/W/X
   geometry.

The first contract is already cross-vehicle. `tsk/lib/bootstrap_profile.py` records
exact-F181, evidence-graded rows for `8965B4512000`, the observed Corolla targets
`8965H1202000`/`8965F1208000`, the verified Camry `8965F3307000`, and the external-source B4/F3/F4 family targets
`8965B4209000`, `8965B4233100`, `8965B4509100`, `8965B4514000`, `8965F3401200`,
`8965F4207000`, and `8965F4201000`. There is no family-prefix fallback. The externally observed newer-Toyota `FEBE0000`
shellcode VMA remains only a linker observation and cannot satisfy any of these gates.

Fixture identity is narrower. The exact repository `d972...` RAM ciphertext and the local
auto-reset `bf624...` package remain exact-gated to `B4512000`. The standard DataFlash
`d489...` package is separately evidenced on `B4512000` and exact `F3307000`. The
CodeFlash range-reader `860f...` is exact-gated only to `F3307000`, where it completed
524288/524288 words with the retained raw SHA. Historical family evidence never implies
byte-for-byte acceptance; a shared `FEBF0000` window authorizes no ciphertext by itself.

Application-retained runtime evidence is narrower again. The built-in inert scheduler
package remains bound to `B4512000` CodeFlash SHA
`21140bbd65e530a9e518a3e84e20e5d85679675bc09cc724cb177bb7c76bafde`. Exact F33 live
startup disproves `FEBF0000` retention and instead proves executable
`FEBFF9F0..FEBFFBFB`; placement is closed but no reversible application-context control
transfer has been recovered. Foreign runtime packages must therefore still be generated
from exact CodeFlash and satisfy their own application-retention/control-transfer gates.

TSK now also carries the exact resolver manifests for `8965H1202000` and `8965F1208000`
as **evidence-only negative-capability regressions**. Both are semantically resolved but
`semantic-resolved-steering-unsupported`: their three-record SecOC queue lacks classic
`0x2E4`/`0x131`, retained-RWX geometry is unresolved, and neither manifest can satisfy the
executable canary-package validator. This lets the field UI report why those exact targets
are blocked without turning a foreign manifest into execution authority.

The host-side bootstrap request builder also models both recovered Denso protocol axes:
old/new routine magic (`45 00` / `45 01`) and CPU0/CPU1 (`memory_id=1` + DID `0203=01...`
versus `memory_id=0` + zero DID `0203`). Those builders are planning semantics only. The
only live built-in canary remains explicitly pinned to the reviewed B4512000 old-stack,
CPU0 values; no F3/F4 or dual-CPU live path is enabled by having the constructor available.

This recovery model and the openpilot integration manifest are independent: proving any
boot/runtime primitive does not select a DBC, safetyParam, steering mode, or longitudinal
topology, and proving a target's openpilot profile does not authorize a payload/runtime
from another calibration.

### Key-backed SecOC versus the future ephemeral bridge

Normal openpilot SecOC remains key-backed. The one-off MAC28 ablation experiment has been
retired: Panda no longer corrupts forwarded stock camera MACs, openpilot no longer suppresses
its own SecOC command messages, and normal Toyota static forwarding blocks are restored.

opendbc now contains a dormant bridge transport for a future separately validated resident
EPS runtime. When explicitly armed, it marks openpilot's own secured lateral `0x2E4` and
`0x131` envelopes with an all-zero MAC28 while preserving the transmitted freshness nibble.
The mode is not a key and is not selected from Toyota platform identity alone. Root openpilot
requires persistent `ToyotaEphemeralSecOCBridge` plus an exact
`ToyotaEphemeralSecOCBridgeF181` match against the current EPS firmware inventory. A valid
`SecOCKey` always takes priority. The bridge is also refused when openpilot longitudinal is
active because the current resident bridge does not cover protected ACC `0x183`.

TSK currently ships and executes only the audited **inert canary**. It does not ship the
704-byte steering bridge, expose a bridge-deployment endpoint, or set the bridge parameters.
The tracked Corolla H/F generation is also a negative applicability result: its EPS receive
census has no classic secured `0x2E4`/`0x131` steering profiles, so the Sienna bridge cannot
be projected onto those targets. Those remain future steps only for an exact target whose
own steering ingress is resolved, after heartbeat/reset-to-stock and isolated-bench steering
validation succeed.

## Manifest required before operational implementation

`/target-profile.html` records these fields and an evidence source for every one. The
read-only Corolla TSS3 platform does not waive this manifest: these fields remain required
before TSK can authorize a key-backed or runtime-backed control path.

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
9. the exact target EPS F181 is present either in production `FW_VERSIONS` or the
   explicitly research-only `TSS3_EXACT_FW_VERSIONS` identity map.
10. The Toyota interface still contains the safety/longitudinal derivation contract.
11. The Toyota controller still contains secured LKA/LTA/ACC command paths.

The audit stores SHA-256 hashes of the reviewed Toyota source files and DBC generator in
the target profile. `Re-audit opendbc` on the target-profile page re-verifies the recovered
key against the current oracle and reruns the source checks after an opendbc patch/submodule
update.

The exact Camry TSS3 research identity now satisfies the audit's F181 source check through
`TSS3_EXACT_FW_VERSIONS`. It still **must not** satisfy the operational audit: the interface
explicitly selects `SafetyModel.noOutput`, so there is no production Toyota safetyParam or
enabled B6 sender. The audit reports that boundary directly. Passing ordinary opendbc
platform tests therefore means "safe to parse/shadow," not "TSK code-ready for steering."

As a sanity check during development, the audit resolves the existing
`TOYOTA_SIENNA_4TH_GEN` / F181 `8965B4509100` configuration as source-ready with
`toyota_secoc_pt_generated`, torque control, EPS scale `73`, default openpilot
longitudinal, and safetyParam `0x849`.

## What the eventual production-control patch must contain

The passive Camry TSS3 platform now supplies exact identity, platform/DBC/CarState,
receiver limits/timing, shadow B6 packing/freshness and source-real Ready/gear state. Before
it can become a production-control port, the corresponding opendbc change still needs:

- complete **stock-captured** B6 28-byte template/cadence, sequence restart and freshness behavior;
- relay-correct stock producer location and exclusive suppression behavior;
- application-context ICU-S slot-4 general-generation permission and measured latency/jitter;
- a validated physical driver-override threshold for the decoded `0x030` torque plus
  motor-Q-current response policy and live `0x351/0x394/0x4A3` fault/recovery transitions;
- a production TSS3 Toyota safety model/parameter rather than `noOutput`;
- controller packing/signing only after the sender contract is complete;
- radar/longitudinal ownership only when those separate architectures are recovered; and
- transition/route tests covering stock LTA/B6, cruise engage/cancel and failure cases.
  P/R/N/D/B and NRTD/READY are already source-real validated on this exact Camry.

Until those values exist, the dedicated TSS3 platform remains intentionally passive rather
than aliasing the target to `TOYOTA_CAMRY_TSS2`, `TOYOTA_COROLLA_TSS2`, or
`TOYOTA_SIENNA_4TH_GEN`.

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
