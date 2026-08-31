# 2026 Camry / F33 exact-target checkpoint

This is the TSK/openpilot-facing checkpoint for the maintainer 2026 Toyota Camry with
EPS application F181 **`8965F3307000 / 8A3113303100`**. The byte-level/static authority
remains `ghidra_rh850_analysis`; this document mirrors only findings that are already
field- or exact-firmware-evidenced and useful to the fork.

The exact Gate-2-patched maintainer Camry is supported by this fork for lateral output; this
does not authorize upstream inclusion or generalize to an unpatched/other F33. The port follows
the ordinary Toyota/openpilot shape on `TOYOTA_CAMRY_TSS3`:
ordinary CarParams, CarController, and Panda safety — no private parameters, no
ephemeral-bridge arming, and no `ALLOW_DEBUG` development mode. It sends deliberately
zero-MAC28 `0x0B6` on Panda bus 0, which this maintainer EPS accepts because it carries the
persistent exact-F33 Gate-2 patch (CodeFlash compare neutralization with deterministic CRC
repair). CORR-135/VAR-087 remain the stock-architecture boundary: factory LTA/LCA steers
with zero B6 through an exact F33 B6-independent internal assist path, so `0x08A`
producer/SecOC ownership must not be conflated with a presumed `0x08A -> B6` transform. No stock-lateral frame block is justified by the exact-F33 accepted surface; request-plane
`0x08A` therefore remains observational rather than an authority veto. System-generated stock
ACC cancel is the one normal feature still unsupported because its TSS3 transmit contract is unrecovered.

## Exact ECU identities and route

Before the physical Toyota-B repin, all three relevant diagnostic endpoints were observed on
**normal-harness routing, ELM327 parameter 1, Panda logical bus 1**. The relay-correct layout
moves the steering/chassis family onto the current **CAN0/CAN2 relay pair**: Panda bus 0 is
the established development B6 TX path, Panda bus 2 is its byte-identical relay mirror, and
Panda bus 1 is the native camera/radar plane. Toyota/GTS+ logical Bus 4 contains Brake
Booster, Skid Control, EPS, SAS, and Airbag behind Central Gateway. These are distinct naming
layers; no missing frame may be used to invent a private EPS stub or second EPS CAN interface.

| ECU | request -> response | exact identity |
|---|---|---|
| EPS | `0x7A1 -> 0x7A9` | F181 `8965F3307000 / 8A3113303100`; F18C `8965033K9011J2740743` |
| FRC / forward recognition camera | `0x792 -> 0x79A` | F181 `8646F3315000`; F18C `TN69400026030404235J`; `0105=8646C06091` |
| Brake/EPB | `0x7B0 -> 0x7B8` | F181 `F152633K0000`; F18C `8954147040CFC1800985`; `0105=8954147040` |

The EPS bootloader F181 is `02 || 32*0x21` on the same physical route.

## Source-real state joins

Controlled passive captures on this exact Camry establish:

- `0x51E B0[7]`: **0 = Not Ready to Drive, 1 = READY**. A logger armed in NRTD saw
  the controlled `0 -> 1` transition at `t=5.213083 s` after capture start.
- `0x127`: full selector enum **`0=P, 1=R, 2=N, 3=D, 4=B`**. The dedicated B capture
  produced `3 -> 4 -> 3`; every retained `0x127` frame passed the Toyota checksum.
- physical steering state is carried by the same TSS3-era FD family already used by the
  passive Camry port (`0x025`, `0x030`, etc.). `0x030` yields source-real physical driver
  torque; the old `0x260/0x262/0x2E4/0x131` Corolla-era steering contract is not present.

### Cruise controls

FRC P5 DIDs `1202/1901/1905/1906/1912/1914/1918/1928` are readable in NRTD. Isolated
button captures and a synchronized CAN+diagnostic capture locate the ordinary momentary
switch carrier at **pre-repin Panda bus 1 `0x0FE`, 32 bytes, ~33.19 Hz**. For bytes `(B3,B4,B6,B7)`:

| state/event | tuple |
|---|---|
| baseline | `3F 00 C3 62` |
| MAIN | `3F 00 C3 66` |
| RES+ | `BF 00 43 62` |
| SET- | `3F 80 C3 22` |
| CANCEL | `3F 40 C3 42` |

Following-distance changes FRC DID `0x1912`; `0x251 B5` and `0x5AF B24` are retained
**candidates**, not promoted OEM semantics from one event. Brake DID `0x102F` is readable;
`0x107E` returns requestOutOfRange in both default and extended sessions.

## Exact CodeFlash acquisition and bootstrap

The exact-target field collector recovered the full configured `0x00000000..0x001FFFFF`
transport range:

- `524288 / 524288` words, 100% coverage;
- zero conflicting duplicates, zero duplicates in the successful pass, zero SPI errors;
- raw 2 MiB SHA-256
  `b588c7258699beee77669d1f5f09bb17ef8b189b941b46f344a07378c3aaa727`;
- lower 1 MiB is populated CodeFlash; upper 1 MiB is erased `0xFF`;
- normalized lower-1-MiB SHA-256
  `42dce8efc42f6ae31718e7713fa2d26bb9191b4a82439778aee4d7afded9b0e7`.

The same acquisition independently proves this exact F33 uses the **old-stack** boot
payload grammar:

1. boot `27 01/02` using the shared `f05f...` SecurityAccess secret;
2. DID `0203 = 00*5`, then zero `0201/0202`;
3. authenticated `RequestDownload` to `FEBF0000`, size `0x1000`;
4. `0x10F0` with `45 00`;
5. `0xFF00` callback execution.

Bootloader SID `0x23` CodeFlash reading was tested first and rejected, so the retained
range-reader is not a generic ReadMemoryByAddress shortcut. The exact 4 KiB range payload
is now committed as `tsk/lib/payload_codeflash_00000000_00200000.bin`, SHA-256
`860f8a3418d23ccfd0861a97efdb9e1d23a8854c3a629b8d7b6821eb93d0b588`.
`tsk/lib/dump_codeflash.py` exact-gates identity, route, NRTD state, payload hash and boot
geometry before PROGRAMMING; it retains partial coverage and tolerates recoverable Panda
SPI errors.

Run it on comma only while stationary in **NRTD**:

```bash
cd /data/openpilot
.venv/bin/python tsk/tools/dump_codeflash.py
```

A partial pass can be resumed by supplying both `--resume-dump` and `--resume-coverage`.

## Target-native B6 / SecOC steering receiver

The exact F33 Rx descriptor table contains all 40 Corolla-H application descriptors plus
only `0x116`, `0x0D8`, and `0x1DA`. Its three protected receive profiles are exactly
**`0x00F`, `0x0D7`, and `0x0B6`**.

For Camry `0x0B6`:

- generated COM PDU **44**, 32 bytes;
- 28 application bytes + FV4/CMAC28 trailer;
- full freshness = FV46 and full authenticator = CMAC128;
- crypto handle 0 uses config `{type=1, selector=4}`; exact target code programs ICU-S
  **command 7**;
- signal 261 = `B3[5:0]`, target-lateral selector; value **11** selects LTA/LCA mode2;
- signal 262 = signed16 `B4:B5`, target steering command;
- physical scale = `1024/17870 deg/count` (~1.00012 mrad/count);
- signal 268 = modulo-64 application sequence;
- signal 265 value 1 suppresses one additive contribution;
- signals 269/270 are `/100` contribution percentages; zero removes each contribution.

Exact mode2 constraints recovered from this image are:

- absolute command envelope **±1745 raw** (~±100 deg);
- maximum delta **78 raw** (~4.47 deg) per effective sequence gap;
- effective sequence gap capped at **8**;
- foreground period is steady **5.000 ms** after one 5.125-ms startup interval;
- the seven-tick B6 receive supervision therefore gives nominal **35 ms** loss timeout.

These are EPS receiver/representation constraints. They are not a substitute for a
production driver-override or motor-current-response policy.

### Target-native generated Tx/status closure

The exact F33 generated-COM tables put the first five normal Tx PDUs at
`0x030 / 0x351 / 0x394 / 0x4A3 / 0x4C8`. Target packers are `0x4CED0` for `0x351`,
`0x4CE08` for `0x394`, and `0x4C000 -> 0x4C14E -> 0x4C7AA` for `0x4A3`.

The current exact-F33 canonical direct-reference census separates three distinct feedback
sources. Driver torque has **9 direct references (7 reads + 2 writes)**. DID `0x1151`
motor Q-current has **6 direct references (4 reads + 2 writes)**. The alternate-current
source used by `0x4A3 B6:B7` has **4 direct references**. That `0x4A3` source remains
`GP-0x50E8` and must **not** be labeled DID `0x1151`, which independently uses
`GP-0x50F2`. The bounded cooperative `C8xxx..D1xxx` control cone still has zero direct
driver-torque references.

### Feedback/status boundaries

- `0x025` signal 189 / DID `0x1036` is Steering Angle Velocity. The recovered monitor uses
  `abs(raw) > 100` with 79-cycle persistence.
- DID `0x1035` Steering Wheel Torque scales `raw/256 N.m`; ±2109 raw is an acquisition
  clamp, **not** a driver-override threshold.
- DID `0x1151` Motor Actual Current Q Axis computes `(raw*100)/0x80`.
- `0x394` is a lossy projection of an exact 17-row F33 internal status table. The fork
  retains compatible candidate sets for each wire tuple; it deliberately does not map
  those internal states to openpilot temporary/permanent faults without live fault and
  recovery dynamics.

## SecOC-key recovery result

Exact field recovery also retained 32 KiB DataFlash, 128 KiB LocalRAM and 64 KiB
GlobalRAM. The bounded CPU-visible key search was negative:

- DataFlash object-15: zero valid copies and zero16 key fields;
- legacy RAM key-table projection: zero valid records;
- exhaustive raw 16-byte candidate scan against retained target SecOC traffic: **zero
  survivors**.

This is consistent with the statically active **ICU-S protected slot-4** architecture. The
secret is not an ordinary DataFlash object and CPU-visible `00`/`FF` reads do not expose or
characterize protected contents. The negative ordinary-memory census therefore cannot be
turned into a DataFlash key-recovery plan. It also does not prove absence of an
application-only transient because the RAM snapshot is post application-to-boot transition.

## Volatile application-runtime signer research

The old low boot staging pocket must **not** be treated as an application resident:
real stock startup overwrites `FEBF0000..FEBF0307`.

A separate exact-target live probe proves an executable high tail survives stock startup:

- **`FEBFF9F0..FEBFFBFB`**, exactly 524 bytes;
- retained byte-for-byte SHA-256
  `89ffed31c24e746a57171e6f3e22f99d1e78d57b63bccb8778c7fe715d18800c`;
- stock `8965F3307000 / 8A3113303100` application returns normally;
- the region lies inside MPU region 1 `FEBF7C00..FEBFFBFC`, supervisor executable.

The exact application also contains an XCP-like write surface:

- request `0x7F7`, response `0x7F8`;
- SET_MTA `0x82C62`, DOWNLOAD `0x81FFE`, MODIFY_BITS `0x820C4`, SHORT_UPLOAD `0x82B1A`;
- validator `0x98F2C` admits **`FEBF7C00..FEBFFBFF`**, covering the full proven tail;
- no configured GET_SEED/UNLOCK callbacks.

The normal EPS bus-1/ELM1 CONNECT-only probe timed out. That is a route/session negative,
not a contradiction of the firmware endpoint.

RID `0x100F` genuinely reaches the stock command-5 crypto state machine, but it uses a
fixed 16-byte private input/result and is **not** a general 7-/36-byte SecOC signer API.
Application UDS has no SID `0x3D` arbitrary WriteMemoryByAddress path. A 312-site indirect
call audit and the recovered fixed-DMAC descriptors have not found a reversible
application-context PC/callback pivot into the XCP-writable tail.

The exact-F33 zero-MAC28 receive resident is a separate, audited static candidate. It fits
within the live-proven high-tail geometry before heartbeat `0xFEBFFBEC` and re-admits only B6
frames that normal verification rejected and whose MAC28 bits are all zero. All other frames
retain the stock verifier. Reset restores stock. What remains missing is automatic deployment,
a concrete application-mode execution pivot, heartbeat confirmation, re-arm after EPS reset,
and live behavior validation.

For **receiver acceptance** the historical option list was: (1) the persistent exact-F33
Gate-2 CodeFlash compare/check disable with deterministic CRC repair, or (2) a reset-to-stock
RAM bridge. This is now **resolved on the maintainer car by option 1**: the EPS carries the
persistent Gate-2 patch, which is why the ordinary port's zero-MAC28 B6 frames are accepted.
The RAM-bridge resident remains an audited static research candidate only — it never became a
deployable runtime (no automatic install, execution pivot, heartbeat, or re-arm flow was
built), and the openpilot port no longer references it. Neither path retrieves the protected
key.

## openpilot state

The checked-out fork implements the exact-F33 port through the normal Toyota/openpilot
architecture — ordinary CarParams, CarController, and Panda safety on `TOYOTA_CAMRY_TSS3`,
with no private arming parameters:

- passive-port baseline root commit `d7d7dfd7e49961e9d35eb7a7681e8756ceee8d04`; the
  native-authority cutover is root `2cfa9274c` ("opendbc: use native F33 lateral authority")
  with nested opendbc `21d165da` ("toyota: use native lateral authority for F33"); final
  native-shape cleanup is opendbc `ae284aaf` plus Panda `4130c4a9`; the same
  cutover removed the private params (`ToyotaEphemeralSecOCBridge`,
  `ToyotaEphemeralSecOCBridgeF181`, `ToyotaTss3DevLateral`, `ToyotaTSS3FrcOracleCapture`)
  from `params_keys.h` and all bridge/oracle arming from `card.py`;
- upstream-request decoding (opendbc `b9e86924`) parses `0x08A` B18:B19 target angle,
  B21 Target Lateral ID, and B26 sequence into read-only CarState observables;
- platform identity is the standard pipeline: exact F181 in production `FW_VERSIONS`
  (EPS `0x7A1`, corroborating camera/ABS) plus the exact Camry CAN census in `FINGERPRINTS`,
  so identification works in READY even when the EPS does not answer F181;
- CarState consumes live `SECOC_SYNCHRONIZATION`, `0x025` steering, `0x030` physical N·m
  driver torque plus its validity/fault-inhibit observables, `0x51E` Ready, `0x127`
  P/R/N/D/B, and cruise state from the camera-bus `TSS3_LATERAL_REQUEST` (`0x08A`
  `CRUISE_OPERATING_LATCH`/`SET_SPEED`);
- CarController sends one zero-MAC28 `0x0B6`/DLC32 frame per scheduled control frame on
  Panda bus 0 with live `0x00F` TRIP/RESET freshness, ID11 while `latActive`, ID0 with
  zeroed companions on release, and a standard angle-rate-limited target;
- Panda safety is the ordinary `toyota` model with the `TSS3` flag (not `ALLOW_DEBUG`):
  TX whitelist is only `0x0B6` bus 0 DLC32 with a relay check, `controls_allowed` is
  cruise-derived from `0x08A` bit 27 on bus 2, and the TX hook enforces target ID 0/11,
  companion percentage bounds, and `steer_angle_cmd_checks` at ±1745 raw with the standard
  rate limits;
- interface: angle control, `radarUnavailable`, stock longitudinal, `dashcamOnly=False`,
  `secOcRequired=False` — no SecOC-key availability state is involved in engagement; other
  research TSS3 platforms (Corolla) stay passive `noOutput`/`dashcamOnly`;
- exact `TOYOTA_CAMRY_TSS3` binding, source-real P/R/N/D/B + Ready replay, generated TSS3
  DBC, and the 179-ID census/fingerprint separation remain intact.

Zero-MAC28 B6 is accepted because this maintainer EPS carries the persistent Gate-2 patch —
no key and no RAM bridge are involved. Factory stock-lateral arbitration remains a research question but is not a runtime gate: no
frame block is justified and `0x08A` Target Lateral ID remains request-plane state, not an
authority grant/veto. System-generated stock ACC cancel remains unsupported until its exact
TSS3 transmit contract is recovered.

The latest failed drive, route `0000002a--c5647fd694`, is useful specifically because it
closes two old bring-up failures rather than creating new safety policy. The deployed build
generated 13,410 active ID11 B6 attempts; 5,359 were rejected by the old custom Panda policy,
and every active B6 attempt carried application byte 6 = `0x04`, asserting signal 265's
additive-contribution suppression bit. The current tree fixes both: active B6 uses byte 6 =
`0x00` with 100/100 contribution fields, and Panda uses ordinary Toyota angle-command safety
without the old sequence/35-ms/stock-request/steering-rate development gates.

## What the FRC computes versus what leaves it

FRC-hosted recorder/Operation-FFD vocabulary proves that the camera domain computes a lateral
request object (`5282`/`5631`: Target Lateral ID, milliradian pinion request, assist, damping)
and separately exposes arbitration/result quantities (`5285`, `57DE`, `5265`). No retained
capture contains those four decisive quantities synchronized with CAN, so an ID11 interval is
request-state evidence—not a proved winner/grant oracle.

The native Panda-bus-1 camera/radar plane contains 22 periodic streams:
`0x020`, `0x123`, `0x160`, `0x180..0x18C`, `0x1A0`, `0x200`, `0x201`, `0x230`,
`0x440`, and `0x450`. The `0x180..0x182` family contains plaintext perception-object slots
with 0.01 m forward range; the family uses ordinary counters/checksums, not the `0x08A`
SecOC trailer. `0x160` remains structured but CORR-138 rejects its former standing
steering-angle-echo identity.

No consecutive `5282` serialization, 28-byte `0x08A` application copy, `0x08A`, or other
proved lateral-command carrier appears on native Bus 1. Physical FRC-versus-radar ownership of
individual Bus-1 IDs is not closed. Therefore we know what request state exists inside FRC,
but **the actual FRC-to-chassis request transport is not identified**; a private gateway/service
handoff remains possible. There is no established `0x08A -> B6` transform.

## Upstream lateral request (0x08A)

The two relay-correct drives recover `0x08A/32` as a lateral-request representation: B21 is Target Lateral ID (observed exactly `0` manual / `11` LTA-LCA / `18` SDG, matching the current GTS+ dictionary), B18:B19 is a signed big-endian angle at the numerically matching exact-F33 B6 controller-equivalent scale, and B26 is a modulo-64 sequence. The shared numeric scale does not prove an `0x08A -> B6` conversion path. In manual state B18:B19
tracks measured `0x025` angle within 0.027% fitted-scale error; under ID11 its
correlation shifts forward toward future measured angle. Two caveats: B21/B26 upper two
bits are zero in every retained frame while the GTS+ diagnostic field is 8-bit, so 6-bit
field boundaries are encoding assumptions; and every retained frame is on the Bus-4
Brake/EPS capture (Panda bus 0 / relay mirror bus 2, zero on bus 1), so the producer is
unknown and the frame must not be labeled a Bus-1 camera message. Exact F33 does not accept `0x08A` as normal ingress and does not list it among its five generated-COM Tx IDs. Its recovered protected `0x0B6` interface is a **separate external cooperative-control ingress**, not a required stock-LTA next hop. Exact F33's B6-inactive `D0218 -> CC48 -> CC60 -> CC50 -> CC62/CC66 -> CC64` path reaches physical steering, so the 73.303384 s of machine-identified factory LTA/LCA with zero B6 is architecturally consistent.

The `0x08A` trailer is also structurally bounded as Toyota ordinary-P5 SecOC: B28 candidate
reset-low2 agrees with preceding authenticated `0x00F` at the reported drive rates, B26/FV4
progress coherently, and the remaining 28 trailer bits are effectively frame-unique. VAR-101
adds the decisive lifecycle boundary: a stationary READY capture has 2,475 continuously
signed `0x08A` frames at about 41 Hz with B21=0 in every frame, all 16 FV4 phases, 98.75%
reset-low2 agreement with live `0x00F`, 99.96% B26 `+1 mod 64`, and frame-unique MAC28.
The protected publisher is therefore an always-on chassis-side service, not an on-demand FRC
request serializer. This does **not** uniquely distinguish Brake/Skid/Brake Booster from
Central Gateway; exact publisher/key-owner identity still requires producer firmware,
source-identifying measurement, or synchronized private-link evidence.

### Complete field census (VAR-088)

A both-drive per-B21-state census over 44,613 deduped bus-0 frames closes every
application byte, and the DBC entry now carries the full field set:

| bytes | field (DBC signal) | closure |
|---|---|---|
| B0,B1,B2,B5,B15,B25,B27 | — | identically zero in every frame |
| B3[3] | `CRUISE_OPERATING_LATCH` | value 8 latch; follows MAIN by 0.17-0.29 s, clears on CANCEL |
| B6 / B7 | `CRUISE_SUBSTATE_1/2` | (0,18) off, (45,71) LTA-active, (44,70) second sub-mode, (0,146) transitional |
| B8:B9, B11:B12 | `REQUEST_WORD_B8`, `REQUEST_WORD_B8_MIRROR` | byte-identical duplicate in 100% of frames; raw -1146..995; uncorrelated (|r|<=0.07) with accel, steering angle, driver torque, target-angle rate |
| B10 | `SET_SPEED` | latched set speed, 1 km/h; zero when cruise off |
| B13:B14, B16:B17 | `RESERVED_16BIT_B13/B16` | constant 0x7FFF sentinels |
| B20[7:6], B22[4] | `CRUISE_STATE_B20`, `CRUISE_STATE_B22` | cruise mirrors of B3[3] (44,587/44,613) |
| B21 | `TARGET_LATERAL_ID` | {0,11,18}; full 19-value GTS+ VAL_ dictionary |
| B23[5] | `COOPERATIVE_SUBSTATE_FLAG` | set in every SDG row; toggles inside LTA/LCA |
| B24 | `LATERAL_REQUEST_LEVEL` | 100 in every LTA/LCA frame, 50 in every SDG frame; percent bounded |
| B26[5:0] | `SEQUENCE` | modulo-64 |
| B28..B31 | `FRESHNESS_*`, `CMAC_MSB28` | FV4+MAC28 trailer geometry |

GTS+ joins: EMPS_P5 DID `0x1CEE` is a four-monitor structured record (Target
Lateral ID + Cooperative Control in Progress Flag + Target Steering Angle
After Output Compensation + Advanced Drive Target Steering Angle), but it is
absent from exact F33's RDBI table, so the EPS-side cooperative target is not
directly pollable. Bus-4 ECU dictionaries carry no lateral-request vocabulary,
so GTS+ cannot name the producer.

## Supported-port validation and remaining research

### Exact maintainer vehicle validation

The software sender exists and receiver acceptance is in place on this car via the installed
persistent Gate-2 patch. The next test is the normal openpilot one: deploy the exact committed
build, engage through stock ACC/openpilot's ordinary `controls_allowed` path, and drive while
checking the transmitted B6 target against measured steering response and EPS/DTC state. No
special Target-Lateral-ID arming rule, stationary sequence ritual, receiver-timeout permission
gate, or guessed driver-override threshold belongs in the implementation.

The recovered ±1745 target envelope, sequence handling, seven-tick receiver loss behavior and
other F33 receiver facts remain useful for diagnosis if the EPS rejects or faults; they are not
extra Panda/openpilot authority rules unless an upstream-style safety semantic independently
requires them. Stock ACC cancel remains unresolved and is not implemented by the port.

### Factory-architecture and unsupported-feature research

Production output remains unauthorized. Separately close:

1. the actual private/public FRC request transport and synchronized `5282/5285/57DE/5265`
   request/winner/grant state;
2. exact `0x08A` physical publisher, protected key owner/profile, and source arbitration—now
   bounded to an always-on chassis service, but not uniquely Brake-family versus Gateway;
3. production-grade source suppression/coexistence, driver override, motor-current response,
   and live `0x351/0x394/0x4A3` inhibit/fault/recovery policy;
4. for a shippable volatile route, automatic resident install, execution pivot, heartbeat,
   re-arm, and reset-to-stock lifecycle.

Do not send `0x08A` to EPS, repeat blind stock-B6-template drives, or infer an
`0x08A -> B6` transform from matching angle scale or topology. Protected key material resides
in protected storage, not ordinary DataFlash. The exact-F33 port is a fork-local development
checkpoint on a Gate-2-patched EPS; it is not upstreamed, and production output remains
unauthorized.
