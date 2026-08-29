# 2026 Camry / F33 exact-target checkpoint

This is the TSK/openpilot-facing checkpoint for the maintainer 2026 Toyota Camry with
EPS application F181 **`8965F3307000 / 8A3113303100`**. The byte-level/static authority
remains `ghidra_rh850_analysis`; this document mirrors only findings that are already
field- or exact-firmware-evidenced and useful to the fork.

Nothing in this document authorizes production steering output. The Camry path remains
`dashcamOnly` / Panda `SafetyModel.noOutput` and emits zero controller CAN. The former exact-F33
bus-0 B6 development sender has been removed from the runtime integration; only passive 0x08A
observation plus analysis/test-only protected-B6 receiver/freshness/safety contracts remain. CORR-135/VAR-087 are the controlling architecture boundary: factory LTA/LCA steers with zero B6 through an exact F33 B6-independent internal assist path, so `0x08A` producer/SecOC ownership must not be conflated with a presumed `0x08A -> B6` stock-LTA transform.

## Exact ECU identities and route

Before the physical Toyota-B CAN0/CAN1 repin, all three relevant diagnostic endpoints
were observed on **normal-harness routing, ELM327 parameter 1, Panda logical bus 1**.
The post-repin 2026-08-27 DTC sweep reaches the same direct diagnostic family on Panda
bus0; these are capture-topology labels, not Toyota/GTS+ Central-Gateway bus numbers:

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

This is consistent with the statically active **ICU-S slot 4** architecture. It does not
prove absence of an application-only transient because the RAM snapshot is post
application-to-boot transition.

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

Current production ranking therefore makes the volatile architecture first-class:

1. **preferred production path:** RAM-only/reset-to-stock application runtime using XCP
   `DOWNLOAD` plus a future concrete reversible volatile callback/control-transfer pivot;
2. RID `0x100F` as a useful command-5 permission/hardware oracle, **not** a signer API;
3. disruptive PROGRAMMING loader only for research/acquisition, not production startup;
4. persistent flash hook **fallback-only**, not the preferred production architecture.

## openpilot state

The checked-out fork contains the passive target-native implementation plus passive
decoding of the recovered upstream lateral request:

- passive-port baseline root commit `d7d7dfd7e49961e9d35eb7a7681e8756ceee8d04`;
- upstream-request decoding (opendbc commit `b9e86924`) parses `0x08A` B18:B19
  signed target angle at `1024/17870` deg/count, B21 Target Lateral ID, and the B26
  modulo-64 sequence into read-only CarState observables;
- the former exact-F33 **B6 development sender was removed** (root commit
  `abf3ca70a`, opendbc commit `b9e86924`, historical commits `15f3550…` /
  `dde0fcf0…`): VAR-081 proves zero stock B6 throughout complete factory
  LTA/LCA-active intervals, so waiting for a stock-captured 28-byte B6 template is
  not a valid integration shape, and the `ToyotaTSS3DevLateral` parameter,
  `toyota_tss3_dev.py`, and their tests are gone;
- exact `TOYOTA_CAMRY_TSS3` F181 binding and source-real P/R/N/D/B + Ready replay;
- generated TSS3 PT DBC, B6 application/freshness/signing analysis helpers, and
  shadow F33 limits;
- 179-ID Camry census deliberately excluded from legacy CAN fingerprinting because the
  Corolla TSS3 census is a strict subset;
- default controller output remains **zero CAN** and CarParams uses `SafetyModel.noOutput`.
- an independent DEVELOPMENT_ONLY **read-only FRC oracle capture** can be armed with
  `ToyotaTSS3FrcOracleCapture`. It is exact-F33/F181-bound, requires passive CarParams,
  `ControlsReady=false`, one Panda reporting ELM327 parameter 1 with controls disallowed,
  and uses `card`'s existing `sendcan` publisher (never a second Panda owner). It emits
  only fixed 8-byte SID-`0x22` requests to the relay-correct post-repin FRC route
  **Panda bus 0 / 0x792** for
  DIDs `0x1601` and `0x1914`, alternated at 10 Hz per DID. The earlier normal-harness
  pre-repin diagnostic route was Panda bus1; current-GTS+ “Bus 1” is a Central-Gateway
  topology label and must not be read as a Panda bus number. If exact positive FRC responses
  never appear or disappear for two seconds, polling stops for that process lifetime.
  This capture path does not set `ControlsReady`, enable a Toyota control safety model,
  or emit any steering/vehicle-control frame.

## Upstream lateral request (0x08A)

The two relay-correct drives recover `0x08A/32` as a lateral-request representation: B21 is Target Lateral ID (observed exactly `0` manual / `11` LTA-LCA / `18` SDG, matching the current GTS+ dictionary), B18:B19 is a signed big-endian angle at the numerically matching exact-F33 B6 controller-equivalent scale, and B26 is a modulo-64 sequence. The shared numeric scale does not prove an `0x08A -> B6` conversion path. In manual state B18:B19
tracks measured `0x025` angle within 0.027% fitted-scale error; under ID11 its
correlation shifts forward toward future measured angle. Two caveats: B21/B26 upper two
bits are zero in every retained frame while the GTS+ diagnostic field is 8-bit, so 6-bit
field boundaries are encoding assumptions; and every retained frame is on the Bus-4
Brake/EPS capture (Panda bus 0 / relay mirror bus 2, zero on bus 1), so the producer is
unknown and the frame must not be labeled a Bus-1 camera message. Exact F33 does not accept `0x08A` as normal ingress and does not list it among its five generated-COM Tx IDs. Its recovered protected `0x0B6` interface is a **separate external cooperative-control ingress**, not a required stock-LTA next hop. Exact F33's B6-inactive `D0218 -> CC48 -> CC60 -> CC50 -> CC62/CC66 -> CC64` path reaches physical steering, so the 73.303384 s of machine-identified factory LTA/LCA with zero B6 is architecturally consistent.

The `0x08A` trailer is also now structurally bounded as Toyota ordinary-P5 SecOC: B28 candidate reset-low2 agrees with preceding authenticated `0x00F` on 19,868/20,615 drive-A frames and 23,093/23,996 eligible drive-B frames; on every same-reset, same-segment B26+1 pair (18,727 A / 21,989 B), candidate message-low2 advances +1. B27 is zero and the remaining 28 trailer bits are effectively frame-unique. This strongly supports `FV4 || MAC28` framing without recovering the exact sender profile, key, or CMAC implementation.

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

## Remaining production gates

Static receiver discovery is no longer the principal blocker, and the old `0x08A -> B6` stock-LTA model is explicitly retired. Before lateral output can be enabled we still need all of the following closures:

1. identify the actual `0x08A` producer and its exact SecOC profile/key-slot/freshness/arbitration ownership;
2. starting from the exact B6-inactive `D0218` path, identify the external/local mode, gain, authority, or state that selects/modulates stock LTA across Target Lateral ID `0/11/18`;
3. choose the openpilot actuation interface. Protected B6 remains a plausible external interface, but if chosen its signer/freshness/suppression/arbitration contract must be recovered independently rather than inferred from stock LTA;
4. validate driver override and motor-Q-current response policy;
5. capture live `0x351/0x394/0x4A3` normal/inhibit/fault/recovery transitions;
6. for the preferred RAM-only signer architecture, prove a reachable application XCP route and a concrete reversible volatile control-transfer primitive.

Do not repeat blind stock-B6-template drives and do not infer an `0x08A -> B6` transform from matching angle scale or bus topology. The FRC `0x1601`/`0x1914` oracle remains useful synchronized corroboration and can help attribute internal F33 state changes. Production output remains `SafetyModel.noOutput` / zero CAN.
