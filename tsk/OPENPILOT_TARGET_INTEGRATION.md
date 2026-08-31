# Target-specific openpilot integration gate

TSK deliberately does not turn a recovered SecOC key into a guessed Toyota platform.
The target must first be observed, then implemented in the checked-out `opendbc_repo`,
then verified stationary/bench-side before TSK permits operational `SecOCKey`
installation.

## 2026-08-30 Camry/F33 reverse-engineering sync status

This fork is synchronized to the exact maintainer 2026 Camry/F33 evidence through
`ghidra_rh850_analysis` VAR-102/CORR-139, including the current application-runtime
placement, relay-correct B6 route, FRC-output boundary, and always-on `0x08A` signer
continuity result. The durable target summary is
[`CAMRY_2026_FINDINGS.md`](CAMRY_2026_FINDINGS.md). Corolla H/F remains useful prior
art, but the Camry port does not depend on transferred addresses or family matching.

The passive Camry port entered the root at baseline commit
`d7d7dfd7e49961e9d35eb7a7681e8756ceee8d04`. The current cutover is root `2cfa9274c`
("opendbc: use native F33 lateral authority") with nested opendbc `21d165da` ("toyota: use
native lateral authority for F33"); final native-shape cleanup is opendbc `ae284aaf` and
Panda `4130c4a9`; the request decoder entered at `b9e86924`, and the
interim private-parameter/ephemeral-bridge/`ALLOW_DEBUG` development path — root
`5fee63cfc`/opendbc `c98872c6`, hardened at root `6dd58cf5e`/opendbc `8da4bb9b` — is
**superseded and removed**. The exact target is `TOYOTA_CAMRY_TSS3`, bound to EPS F181
`8965F3307000 / 8A3113303100`. The port now follows the ordinary Toyota/openpilot shape:
normal CarParams/CarController/Panda safety, no private parameters, and zero-MAC28 B6
accepted by the Gate-2-patched maintainer EPS. It remains a fork-local development
checkpoint, **not production steering authorization** and not upstream.

The status vocabulary below is deliberate: **implemented** means the code path is present;
**implemented-read-only** means only evidence acquisition/inspection is exposed;
**prepared-but-hardware-gated** means host-side code or transport scaffolding exists but
cannot be promoted operationally without the named live proof; **intentionally-not-applicable**
means current firmware evidence disproves that transfer for the named target; and
**blocked-by-live-policy** means the target-native static contract is sufficiently recovered
but production behavior still requires live authority/safety evidence; **not-yet-implementable**
means no correct implementation primitive has yet been recovered.

| RE result / capability | status | OpenPilot/TSK implementation boundary |
|---|---|---|
| exact F33 identity / route | **implemented-read-only** | EPS `0x7A1->0x7A9`, FRC `0x792->0x79A`, Brake `0x7B0->0x7B8`, all on the pre-repin normal-harness `(Panda bus1,param1)` route, are retained in `tsk.lib.camry_f33`; no family-prefix matching |
| exact F33 CodeFlash acquisition | **implemented** | `tsk/lib/dump_codeflash.py` and `tsk/tools/dump_codeflash.py` exact-gate F181, route, NRTD Ready=0, payload SHA and boot geometry; the proven 2 MiB range-reader fixture is bundled and partial coverage is resumable |
| F33 authenticated-RAM bootstrap | **implemented** | exact target proved old-stack boot SA, zero `0203/0201/0202`, `FEBF0000+0x1000`, `0x10F0 45 00`, and `0xFF00`; this does not imply application retention |
| F33 DataFlash / RAM recovery | **implemented-read-only** | exact DataFlash/LocalRAM/GlobalRAM evidence is retained; CPU-visible SecOC key search is negative, consistent with active ICU-S slot 4; no key is fabricated from the negative |
| F33 Ready / full gear state | **implemented-read-only** | source-real `0x51E B0[7]` NRTD/READY and `0x127` `P/R/N/D/B = 0/1/2/3/4` are parsed and replay-tested |
| F33 cruise switch observation | **implemented-read-only** | FRC P5 DIDs and the pre-repin Panda-bus1 `0x0FE/32` MAIN/RES+/SET-/CANCEL carrier are retained; following-distance `0x251/0x5AF` joins remain candidates |
| F33 protected B6 receiver / SecOC geometry | **implemented** | exact PDU44, 28-byte application + FV4/CMAC28, FV46/CMAC128, slot4/command7, Target Lateral ID, signed target angle, sequence, companion fields and exact target limits/timing are represented in opendbc helpers/DBC; exact-F33 Gate-2 compare neutralization plus CRC repair admits deliberately zero-MAC28 development frames |
| F33 port / DBC / CarState | **implemented** | `TOYOTA_CAMRY_TSS3` is a normal platform: exact F181 in production `FW_VERSIONS` plus the exact CAN census in `FINGERPRINTS` (identifies in READY without an EPS F181 reply), generated TSS3 DBC, source-real Ready/gear/cruise-state replay, live `SECOC_SYNCHRONIZATION`, physical `0x030` N·m driver torque, and camera-bus `TSS3_LATERAL_REQUEST` cruise state. The raw torque-invalid/fault-inhibit bits remain DBC observables; no guessed `steeringPressed` threshold or temporary/permanent fault mapping is promoted into CarState. Other research TSS3 platforms (Corolla) remain passive `noOutput`/`dashcamOnly` |
| F33 synchronized FRC operating-state capture | **superseded-removed** | the root `ToyotaTSS3FrcOracleCapture` param and `toyota_tss3_oracle.py` capture path were removed with the private-parameter architecture; the decisive Operation-FFD `5282/5285/57DE/5265` synchronized capture is still absent and must be re-acquired with separate read-only tooling when needed |
| FRC public-output boundary | **implemented-read-only** | native Panda bus 1 carries the 22-stream `0x020/0x123/0x160/0x180..0x18C/0x1A0/0x200/0x201/0x230/0x440/0x450` camera/radar census and plaintext perception records; no consecutive `5282`, no `0x08A`, and no proved public lateral-request carrier. Internal FRC request ownership does not identify its private handoff to the chassis signer |
| F33 generated Tx/status + `0x394` classifier | **implemented-read-only / analysis-only** | exact `0x030/0x351/0x394/0x4A3/0x4C8` Tx/packer geometry and the 17-row `0x394` classifier remain in the analysis evidence. The native runtime port does not promote the unresolved classifier into CarState temporary/permanent faults. |
| F33 lateral sender / safety | **implemented (fork-local)** | ordinary openpilot lateral engagement (`CC.latActive`): CarController sends one zero-MAC28 `0x0B6`/DLC32 frame per scheduled control frame on Panda bus 0 with live `SECOC_SYNCHRONIZATION` freshness, ID11 while active, ID0 with zeroed companions on release, and a standard angle-rate-limited target. Panda safety is the ordinary `toyota` model with the `TSS3` flag — TX whitelist is only `0x0B6` bus 0 DLC32 with a relay check, `controls_allowed` is cruise-derived from `0x08A` bit 27 on bus 2, and the TX hook enforces target ID 0/11, companion bounds, and `steer_angle_cmd_checks`. No longitudinal output |
| F33 application-retained RAM bridge | **implemented-static / research-only** | exact-F33 resident re-admits only rejected zero-MAC28 B6, fits before heartbeat `0xFEBFFBEC`, and resets to stock; no automatic install/execution-pivot/heartbeat/arm path was ever built, and the openpilot port no longer references it in any way |
| persistent Gate-2 patching | **installed on the maintainer EPS / policy-open** | the exact-F33 compare/check disable with deterministic CRC repair is present on this maintainer car, which is why the ordinary port's zero-MAC28 B6 frames are accepted. Persistent flash risk and upstream acceptability remain separate policy questions; this route does not recover the protected key |

### Normal port shape

The exact Camry implementation is now an ordinary openpilot platform — the interim
"passive default plus explicit development cutout" split is gone:

- `ToyotaFlags.TSS3` and `ToyotaFlags.SECOC` are both set without inheriting TSS2.
- Exact identity uses the standard pipeline: the exact EPS F181 and corroborating
  camera/ABS entries live in production `FW_VERSIONS`, and the exact Camry CAN census is
  registered in `FINGERPRINTS`, so identification also works in READY when the EPS does not
  answer F181.
- `toyota_tss3_pt_generated` includes target-evidenced state/status and B6 fields. `0x08A`
  decoding remains observation/state-input only; there is no `0x08A -> B6` transform.
- CarState consumes live `SECOC_SYNCHRONIZATION`, source-real steering angle/rate, wheel
  speed, brake/gas, `0x030` physical N·m driver torque, full P/R/N/D/B, Ready, and cruise
  state from the camera-bus `TSS3_LATERAL_REQUEST` (`0x08A`
  `CRUISE_OPERATING_LATCH`/`SET_SPEED`). The raw torque-invalid/fault-inhibit signals remain
  in the DBC, but the port deliberately leaves `steeringPressed` and temporary/permanent
  steering-fault policy neutral because those mappings are not recovered.
- Interface for `TOYOTA_CAMRY_TSS3`: angle control, `radarUnavailable`, stock longitudinal,
  `dashcamOnly=False`, `secOcRequired=False`. No SecOC-key availability state is involved in
  engagement — the local EPS Gate-2 patch makes B6 authentication keyless for this platform.
  Other research TSS3 platforms (Corolla) stay passive `noOutput`/`dashcamOnly`.
- There are no private parameters and no `ALLOW_DEBUG` development mode; engagement follows
  the standard openpilot path. Stock longitudinal remains excluded from openpilot control,
  and no `0x183` output exists.

Exact firmware closes the **external B6 receiver** command envelope: Target Lateral ID 11
selects LTA/LCA mode2; signed B4:B5 target angle uses `1024/17870 deg/count`; absolute
envelope is ±1745 raw; delta is 78 raw per effective modulo-64 gap with cap 8; foreground
is 5 ms and the seven-tick receive deadline is nominally 35 ms. Retained factory LTA/LCA
has zero B6 and exact F33 has a B6-independent stock assist path, so the B6 sender is a
separate external actuation interface—not a reconstruction of stock LTA.

The practical next test is the ordinary openpilot drive path, not another custom arming
ladder: deploy the exact committed revisions, engage through stock ACC/openpilot's normal
`controls_allowed` path, and compare transmitted B6 targets with measured steering response
and EPS/DTC state. The recovered receiver timeout/sequence behavior remains diagnostic
information, not extra Panda permission policy. No stock B6 was retained, so unresolved
factory arbitration remains an evidence boundary rather than a request-plane engage veto.

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

For H/F Corolla and exact F33 Camry, the TSS3 DBC models protected FD `0x0B6`
receiver fields recovered target-natively. F33 closes PDU44, Target Lateral ID, signed target
angle, modulo-64 sequence, FV46/FV4/CMAC28, and receiver limits. For the exact Camry, the
normal TSS3 controller sends zero-MAC28 B6 on Panda bus 0 as part of the ordinary port —
accepted through the installed Gate-2 patch, with no EPS-bridge parameters and no development
safety mode. It does not claim a Toyota stock template, a real CMAC key, a solved FRC
transport, or production source arbitration. Protected `0x183` longitudinal output remains
excluded. The Corolla TSS3 platform stays read-only/passive.

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

### Key-backed SecOC versus the exact-F33 zero-MAC28 path

Normal openpilot SecOC remains key-backed. The old broad MAC28-ablation experiment is
retired: Panda does not corrupt forwarded stock MACs, and ordinary Toyota forwarding stays
stock. The exact-F33 path is instead receiver-side and keyless.

opendbc builds its own protected-FD B6 application for `TOYOTA_CAMRY_TSS3`, retains live
`SECOC_SYNCHRONIZATION`-derived freshness, and marks only that generated B6 with an all-zero
MAC28. The Gate-2 patch installed on this maintainer EPS accepts it after normal verification
rejects it. This is not a key and involves no private parameters, no `SecOCKey` state, and no
non-release gating beyond the fork itself. No longitudinal output exists, so protected ACC
`0x183` is untouched. On any other EPS — including another F33 without the patch — the
zero-MAC frames would be rejected by the stock verifier and the port must not be assumed to
work.

Historically there were two receiver-side deployment classes:

1. the persistent CodeFlash Gate-2 compare/check disable with deterministic CRC repair —
   now installed on this maintainer car and load-bearing for the port;
2. the reset-to-stock exact-F33 RAM resident that re-admits only rejected zero-MAC28 B6 —
   still an audited static research candidate with no install/execution-pivot/heartbeat/arm
   flow ever built; the port no longer references it.

TSK ships only the audited **inert canary** for bench research. It does not deploy any F33
steering resident. Neither route retrieves the protected key.

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
7. `RADAR_ACC`/default-long behavior agrees with `longitudinal_control`; a TSS3 platform
   handled by its own interface branch is checked against the forced stock-longitudinal
   contract instead.
8. The source-derived Toyota `safetyParam` equals reviewed `safety_flags`; for a TSS3
   platform with its own interface branch the audit derives EPS scale + `STOCK_LONGITUDINAL`
   + `TSS3` bits.
9. the exact target EPS F181 is present either in production `FW_VERSIONS` or the
   explicitly research-only `TSS3_EXACT_FW_VERSIONS` identity map.
10. The Toyota interface still contains the safety/longitudinal derivation contract.
11. The Toyota controller still contains secured LKA/LTA/ACC command paths.

The audit stores SHA-256 hashes of the reviewed Toyota source files and DBC generator in
the target profile. `Re-audit opendbc` on the target-profile page re-verifies the recovered
key against the current oracle and reruns the source checks after an opendbc patch/submodule
update.

The exact Camry TSS3 identity satisfies the audit's F181 source check through production
`FW_VERSIONS`, and — as a TSS3 platform handled by its own interface branch — the audit now
resolves the real output contract: ordinary `toyota` safety, angle control, stock
longitudinal, and safetyParam = EPS scale (73) + `STOCK_LONGITUDINAL` + `TSS3` bits. Passing
opendbc platform and safety tests means the port matches its static contract; it does not
authorize road use on any other EPS (the Gate-2 patch is this car's acceptance mechanism), or
close production signer/source-arbitration policy.

As a sanity check during development, the audit resolves the existing
`TOYOTA_SIENNA_4TH_GEN` / F181 `8965B4509100` configuration as source-ready with
`toyota_secoc_pt_generated`, torque control, EPS scale `73`, default openpilot
longitudinal, and safetyParam `0x849`.

## Supported exact-F33 port boundary and remaining research

The exact Gate-2-patched maintainer Camry has a normal fork-local lateral-control port:
identity/DBC/CarState, B6 packing/freshness, ordinary Toyota Panda safety, fixed relay-open
forwarding, and source-real Ready/gear/cruise state are implemented through standard
openpilot interfaces. That support does not generalize to unpatched F33 software or other
TSS3 platforms.

The bounded follow-ups are not lateral-output gates:

- **System-generated stock-ACC cancel is unsupported.** Physical CANCEL is decoded, but no
  safe TSS3 transmit PDU is recovered; do not spoof protected `0x0FE` or reinterpret
  longitudinal `0x0C9`/`0x0CA` values as a cancel bit.
- A physical driver-torque value is decoded, but no exact driver-override threshold is
  recovered, so openpilot `steeringPressed` is intentionally not synthesized from a guessed
  number.
- F33 fault/inhibit observables are decoded, but temporary/permanent openpilot fault classes
  remain unmapped until asserted/recovery dynamics prove the classification.
- `0x08A` producer/private-middle stock-authority attribution remains architecture research;
  VAR-104 proves it is not an EPS ingress/grant and therefore not a Panda/CarController veto.
- A RAM-only/reset-to-stock signer remains desirable future research to eliminate the
  persistent Gate-2 development patch; it is not part of the current driving stack.

No private arming Params, runtime diagnostic oracle, fake SecOC-key state, ALLOW_DEBUG steering
mode, Python shadow safety, dynamic harness switch, request-plane coexistence veto, or custom
Panda receiver timing/sequence policy belongs in the supported port.

## Generic key-backed stationary gate (not the current F33 port)

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

The key-backed path above does not apply to the exact-F33 port: `TOYOTA_CAMRY_TSS3`
engagement involves no `SecOCKey` (`secOcRequired=False`). Its persistent Gate-2 patch was
independently preflighted, applied, reboot-verified, and subsequently exercised in live
openpilot routes. TSK therefore does not impose a second private stationary-install gate on
the supported F33 port.
