# 2026 Camry / F33 exact-target checkpoint

This is the TSK/openpilot-facing checkpoint for the maintainer 2026 Toyota Camry with
EPS application F181 **`8965F3307000 / 8A3113303100`**. The byte-level/static authority
remains `ghidra_rh850_analysis`; this document mirrors only findings that are already
field- or exact-firmware-evidenced and useful to the fork.

Nothing in this document authorizes production steering output. The default Camry path remains
`dashcamOnly` / Panda `SafetyModel.noOutput` and emits zero controller CAN. The fork now also stages
an exact-F33, non-release development sender behind explicit live gates; that sender is intentionally
invalid-MAC and exists for the Gate-2 bypass experiment, not as production TSS3 support.

## Exact ECU identities and route

All three relevant diagnostic endpoints were observed on **normal-harness routing,
ELM327 parameter 1, logical bus 1**:

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
switch carrier at **bus 1 `0x0FE`, 32 bytes, ~33.19 Hz**. For bytes `(B3,B4,B6,B7)`:

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

The checked-out fork already contains the passive target-native implementation:

- passive-port baseline root commit `d7d7dfd7e49961e9d35eb7a7681e8756ceee8d04`;
- exact F33 development gating is retained in root commit
  `15f3550365e2eee54ca5645ae9c24d9d41ae4f31` and opendbc commit
  `dde0fcf0fbaf875750c54a072b0dcb3857f8829b`;
- exact `TOYOTA_CAMRY_TSS3` F181 binding and source-real P/R/N/D/B + Ready replay;
- generated TSS3 PT DBC, B6 application/freshness/signing helpers, and shadow F33 limits;
- 179-ID Camry census deliberately excluded from legacy CAN fingerprinting because the
  Corolla TSS3 census is a strict subset;
- default controller output remains **zero CAN** and CarParams uses `SafetyModel.noOutput`;
- a DEVELOPMENT_ONLY exact-F33 path can opt into `TSS3_DEV_LATERAL` only on non-release builds after
  an exact `8965F3307000` match, relay-correct bus-0 topology, a stock-validated 28-byte B6 template,
  1–3 control-frame cadence, and explicit Gate-2-bypass plus exclusive-B6-authority attestations;
- that development sender intentionally emits an invalid MAC and therefore does not constitute a
  production SecOC signer or production TSS3 output support.
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

## Remaining production gates

Static receiver discovery is no longer the principal blocker. Before lateral output can
be enabled we still need all of the following live/architecture closures:

1. a relay-correct synchronized factory-operating-state capture. Two blind drives already
   retained healthy protected traffic with zero B6, so the next discriminator is FRC
   `0x1601` (LTA Switch/Control) plus `0x1914` (ACC Control in Operation) in the normal
   loggerd route. If that machine-proves the expected factory operating interval while B6
   remains absent, the upstream FRC/Brake transformation or a non-COM/internal EPS path
   becomes the next RE boundary rather than another blind B6 drive; if B6 appears, retain
   its exact cadence/full 28-byte template/secondary fields, sequence restart and freshness;
2. proof of exclusive stock-B6 producer suppression / relay authority;
3. application-context ICU-S slot-4 **general generation permission and latency/jitter**;
4. validated driver-override and motor-Q-current response policy;
5. live `0x351/0x394/0x4A3` normal/inhibit/fault/recovery transitions;
6. for the preferred RAM-only signer architecture, a reachable application XCP route and
   a concrete reversible volatile control-transfer primitive.

Until those are closed, the passive implementation and shadow safety helpers are analysis
infrastructure only.
