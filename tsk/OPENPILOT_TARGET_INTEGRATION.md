# Target-specific openpilot integration gate

TSK deliberately does not turn a recovered SecOC key into a guessed Toyota platform.
The target must first be observed, then implemented in the checked-out `opendbc_repo`,
then verified stationary/bench-side before TSK permits operational `SecOCKey`
installation.

## 2026-08-24 reverse-engineering sync status

This fork has been reconciled against `ghidra_rh850_analysis` commit `ad86576`, which
contains the Corolla TSS3/openpilot prior-art audit plus the 2023 public-route and Span
2025 moving-rlog evidence. The H/F manifest copies below remain exact-image evidence;
whole-vehicle routes are kept as separate specimens unless an exact F181 join exists.

The checked-out opendbc fork now includes read-only Corolla TSS3 integration at
`200dfa78` (`toyota: add read-only Corolla TSS3 integration`). That implementation is an
evidence-acquisition checkpoint, not a production steering authorization.

The status vocabulary below is deliberate: **implemented** means the code path is present;
**implemented-read-only** means only evidence acquisition/inspection is exposed;
**prepared-but-hardware-gated** means host-side code or transport scaffolding exists but cannot
be promoted operationally without the named live proof; **intentionally-not-applicable** means
current firmware evidence disproves that transfer for the named target; and
**not-yet-implementable** means the target-native contract needed to write correct openpilot code
has not been recovered yet.

| RE result / capability | status | OpenPilot/TSK implementation boundary |
|---|---|---|
| H/F authenticated-RAM bootstrap transfer | **implemented** | exact `8965H1202000` / `8965F1208000` boot geometry is recognized; exact ciphertext remains a separate gate |
| H/F semantic runtime resolver outputs | **implemented-read-only** | exact RE-generated manifests are bundled as negative-capability evidence; they report `semantic-resolved-steering-unsupported`, never satisfy the executable runtime-package gate, and expose no bridge execution |
| historical B4 payload-family evidence | **implemented** | retained as bootstrap evidence but no longer treated as byte-for-byte proof for the local Sienna `d972...` fixture |
| old/new UDS + CPU0/CPU1 bootstrap request geometry | **prepared-but-hardware-gated** | pure request builders model memory-ID, DID `0203`, and `45 00`/`45 01`; the live built-in B451 path remains pinned to its reviewed single-CPU/old-stack byte sequence and no foreign live target is enabled by these builders |
| KEYLESS-006 application-SA LocalRAM mirror | **implemented-read-only** | SID `0x23` reads the exact B451/H/F mirror after exact F181 identification; no automatic SEND_KEY or write |
| software-only execution without boot SecurityAccess | **not-yet-implementable** | the current keyless audit recovers no attacker-selected-PC path that bypasses the independent boot `27 01/02` gate; TSK does not pretend application-SA disclosure is a boot-SA bypass |
| boot `27 01/02` failure timer | **implemented** | live canary handles NRC `0x37` with one bounded post-delay seed retry; no preemptive delay or persistent-lock assumption |
| Span `8965F1208000` direct route | **implemented** | `(bus1,param1)` is recorded as dynamically proven for that specimen, not a Toyota-B universal |
| XCP F4/volatile DAQ observer | **implemented-read-only** | all current RE read/DAQ profiles, including `secoc-verification-state`, are available; source-memory writers/page-copy paths remain absent and firmware-excluded SecOC command-5 cells are not presented as XCP-readable |
| XCP shadow retention across boot handoff | **prepared-but-hardware-gated** | RE proves the application XCP shadow contents can survive the handoff, but no attacker-selected control-transfer consumer is recovered; TSK therefore does not convert retention into a write/pivot or execution endpoint |
| current B451 inert runtime package | **prepared-but-hardware-gated** | current SHA-bound manifest/audit + unchanged canary binary are installed; live execution still requires isolated-bench acknowledgment and the canary/scheduler/reset proof is not yet recorded |
| H/F classic Sienna steering bridge | **intentionally-not-applicable** | their EPS receive census has no classic `0x2E4/0x131`; these manifests are regression evidence, not steering deployment targets |
| command-5 RAM signing proxy | **prepared-but-hardware-gated** | TSK surfaces the current B451 dispatcher/record/selector/mailbox geometry as static evidence only; live ICU-S protected-slot-4 command-5 permission is unknown, so the write-capable mailbox client/binary are not imported and execution is not exposed |
| 704-byte Sienna steering bridge | **prepared-but-hardware-gated** | openpilot/opendbc contains dormant exact-F181/lateral-only transport support; TSK ships no bridge binary/deployment endpoint and does not arm its params until canary, scheduler, queue-capture, COM-delivery, and steering proofs pass |
| XCP F0/EC/E4 write/pivot paths | **prepared-but-hardware-gated** | kept RE-only; field tooling intentionally contains no source-memory writer/page-copy/pivot command builder |
| persistent Gate-2 patching | **intentionally-not-applicable** to the production path | patch/restore evidence remains RE-side; the product direction prefers ephemeral/reset-to-stock behavior |
| newer-Toyota Corolla TSS3 platform/DBC/CarState | **implemented-read-only** | opendbc `200dfa78` adds `TOYOTA_COROLLA_TSS3`, a dedicated CAN-FD PT DBC, the observed Span bus-1 fingerprint, runtime bus0-vs-bus1 state-topology selection, and an evidence-bounded CarState. It is `dashcamOnly` with Panda `noOutput`; the Toyota controller hard-returns zero CAN messages. |
| newer-Toyota production lateral controller/safety | **not-yet-implementable** | exact H/F firmware closes the B6 EPS receiver contract, but sender cadence/full payload, SecOC freshness/source ownership, stock-source suppression, driver-torque/readiness/fault semantics and production limits still require a firmware-identified relay-correct stock-LTA capture and upstream sender closure. |

This table is the durable repo-to-repo audit checkpoint. A later session should change a row
only when new firmware/dynamic evidence changes the boundary; it should not rediscover these
same distinctions from scratch.

### Read-only Corolla TSS3 checkpoint

The initial platform deliberately separates **observability** from **control**:

- `ToyotaFlags.TSS3` is a control-generation flag and remains independent from
  `ToyotaFlags.SECOC`; the new platform carries both because the tracked H/F specimens
  independently support both properties. It does **not** inherit `ToyotaFlags.TSS2`.
- `toyota_tss3_pt_generated` defines only evidence-backed state fields plus the exact H/F
  B6 receiver fields. B6 is present for inspection/round-trip tests only; no sender path is
  enabled.
- CarState promotes `0x025` steering angle/rate, `0x0AA` wheel speed, `0x101` brake and
  `0x116` gas. `0x127` promotes only the dynamically observed raw `3=D`; other gears remain
  `unknown`. `0x176` remains inspectable in the DBC but cruise is held neutral until an
  active transition is captured. Legacy `0x260/0x262` steering torque/fault semantics are
  not transplanted.
- The provisional 147-message CAN fingerprint comes from Span's 2026-07-29 moving rlog.
  That source has MOCK `carParams` and no F181, so it is a whole-vehicle topology fingerprint,
  not an exact `8965F1208000` firmware join. No guessed `FW_VERSIONS` row is added.
- When startup CAN shows `0x025/32` + `0x0AA/8` only on logical bus 1, the read-only parser
  follows the observed unmodified Toyota-B CAN1 path. Otherwise it defaults to bus 0 for
  the intended relay-correct topology. This is parser placement only; it does not claim
  producer-side attribution or stock-source suppression.
- `CarParams.dashcamOnly=True`, the safety model is `noOutput`, radar parsing is disabled,
  longitudinal control is disabled, and `CarController.update()` returns no CAN sends even
  for an enabled lateral/longitudinal control request.

The complete Span rlog was replayed through this parser after implementation: all 5,900
post-startup samples remained `canValid`, speed reached ~6.58 m/s, brake/gas toggled, the
steering range matched the independent RE artifact, and gear remained D. This validates the
read-only parser against the available dynamic evidence without promoting missing semantics.

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

For H/F Corolla, the new DBC additionally models the exact protected FD `0x0B6` receiver
fields recovered from firmware: Target Lateral ID, signed target steering angle, and the
modulo-64 sequence. This is intentionally **not** an extension of the sender contract. The
TSS3 controller exits before all existing Toyota sender logic and emits no CAN traffic until
the B6 sender/authentication/suppression/safety contract is closed.

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
`8965H1202000`/`8965F1208000`, and the external-source B4/F3/F4 family targets
`8965B4209000`, `8965B4233100`, `8965B4509100`, `8965B4514000`, `8965F3401200`,
`8965F4207000`, and `8965F4201000`. There is no family-prefix fallback. The externally observed newer-Toyota `FEBE0000`
shellcode VMA remains only a linker observation and cannot satisfy any of these gates.

Fixture identity is narrower. The exact repository `d972...` RAM ciphertext, the committed
DataFlash `d489...`, and the local auto-reset `bf624...` package are currently exact-gated
to `B4512000` in TSK. Historical B4 family evidence remains recorded, but does not by itself
prove byte-for-byte acceptance of this repository fixture. A shared `FEBF0000` window does
not authorize those ciphertexts on another calibration.

Application-retained runtime evidence is narrower again. The built-in inert scheduler
package is bound to `B4512000` CodeFlash SHA
`21140bbd65e530a9e518a3e84e20e5d85679675bc09cc724cb177bb7c76bafde`; foreign runtime
packages must be generated offline from their own exact CodeFlash and imported into TSK.
Live substitution additionally requires target-specific evidence for the post-auth
short-chunk primitive; cross-vehicle bootstrap reuse does not imply MEM-SAFE-001.

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
9. `FW_VERSIONS[CAR.<platform>]` contains the exact target EPS F181.
10. The Toyota interface still contains the safety/longitudinal derivation contract.
11. The Toyota controller still contains secured LKA/LTA/ACC command paths.

The audit stores SHA-256 hashes of the reviewed Toyota source files and DBC generator in
the target profile. `Re-audit opendbc` on the target-profile page re-verifies the recovered
key against the current oracle and reruns the source checks after an opendbc patch/submodule
update.

The current Corolla TSS3 read-only platform is expected **not** to satisfy this operational
audit yet: it intentionally has no exact target `FW_VERSIONS` join, no production Toyota
safetyParam, and no enabled B6 sender. Passing the ordinary opendbc platform tests therefore
means "safe to parse," not "TSK code-ready for steering."

As a sanity check during development, the audit resolves the existing
`TOYOTA_SIENNA_4TH_GEN` / F181 `8965B4509100` configuration as source-ready with
`toyota_secoc_pt_generated`, torque control, EPS scale `73`, default openpilot
longitudinal, and safetyParam `0x849`.

## What the eventual production-control patch must contain

The read-only Corolla TSS3 platform now supplies the platform/DBC/CarState scaffold. Before
that platform can become a production-control port, the corresponding opendbc change must
add the remaining evidence-backed pieces:

- exact EPS F181 and the other essential firmware fingerprints obtained from the same
  captured target;
- complete B6 sender payload/cadence plus SecOC freshness/key/source ownership;
- relay-correct stock producer location and suppression behavior;
- generation-native driver-torque, EPS response/readiness/fault semantics and validated
  actuator limits for Panda safety;
- a production TSS3 Toyota safety model/parameter rather than `noOutput`;
- controller packing/signing only after the sender contract is complete;
- radar/longitudinal ownership only when those separate architectures are recovered; and
- transition/route tests covering stock LTA, P/R/N/D, cruise engage/cancel and failure cases.

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
