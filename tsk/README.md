# TSK Toyota TSS 3 field tooling

This branch is research tooling for determining whether known Toyota/Denso EPS SecOC
recovery paths transfer to another calibration without silently importing Sienna-specific
assumptions. Unknown fingerprints are evidence, not automatic compatibility: the tooling
may probe an unknown target, but stateful transfer paths retain explicit calibration
boundaries and recovered keys are not trusted until they authenticate captured vehicle
traffic.

For the exact maintainer 2026 Camry/F33 checkpoint, including ECU identities, full
P/R/N/D/B + Ready joins, the completed CodeFlash acquisition, target-native B6/SecOC
receiver, passive opendbc port, key-recovery negative and current RAM-only signer boundary,
see [`CAMRY_2026_FINDINGS.md`](CAMRY_2026_FINDINGS.md).

## Install and preflight

Install the public `kai` branch with:

```text
installer.comma.ai/kaikozlov/kai
```

Before connecting the car harness, enable SSH normally in comma settings and check:

```bash
cd /data/openpilot
git branch --show-current       # kai
git rev-parse HEAD
curl http://127.0.0.1:11111/api/health
```

The launcher writes the web-server log to `/cache/tsk/logs/tsk-web.log`. The offroad
alert shows the reachable web URL.

## Web UI model

The TSK Manager UI is organized around the operator rather than the research chronology:

- **Recovery** is the default dashboard. It projects backend state into one next action and
  a visible sequence: identify EPS -> discover the target SecOC surface -> confirm a
  recovery route when needed -> recover/cryptographically verify key material -> review
  the target-specific openpilot integration -> implement/audit that exact target in
  `opendbc_repo` -> validate a stationary/bench session -> install the already recovered
  key. Key recovery and operational installation are
  deliberately different states.
- **Research** keeps the full diagnostic toolbox grouped by purpose (observe/map,
  programming, memory/security, and transfer experiments) without giving those tools the
  same visual weight as the normal recovery path.
- **System** contains evidence export, cached-data/key management, connection details,
  software switching, and reboot actions.

Every secondary operation page shares the same responsive shell on phone, tablet, and
desktop. The page header shows the currently known F181 and physical route, while badges
make vehicle-state and risk boundaries explicit (`READY`, `NOT READY`, `PASSIVE`,
`READ ONLY`, `RESETS EPS`, `COUNTED ATTEMPT`, etc.). Stateful or disruptive experiments
**never start merely because their page was opened**; the operator must press the explicit
run control after seeing those constraints. The Application `03/04` cross-calibration
SEND_KEY retains its additional one-attempt arming checkbox.


## Risk model: uncertainty should limit interpretation, not observation

TSK gates operations by their **operational consequence**, not by how completely a
calibration is understood. Unknown F181s are expected during research; lack of a static
model is not by itself a reason to suppress low-cost evidence collection.

- **Passive/read observation:** CAN capture, identity/DID reads, DTC reads, bounded SID
  `0x23` reads, and XCP `F4` reads run on unknown targets. Calibration-specific address
  meanings are annotations only.
- **Transient diagnostic state:** session changes, REQUEST_SEED, programming handoff/reset
  probes, and temporary XCP DAQ configuration may perturb volatile ECU state but are
  useful cross-calibration observations. They remain bounded and use cleanup/reappearance
  checks rather than exact-F181 compatibility gates.
- **Counted or consequential writes:** cross-calibration SEND_KEY attempts require explicit
  arming. WDBI, authenticated RequestDownload/TransferData, RoutineControl that executes a
  payload, flash/erase, and similar operations require the evidence appropriate to the
  write they perform.
- **Persistent/actuation paths:** recovered-key installation and vehicle-control output keep
  the strongest profile, source-audit, and stationary verification gates.

The practical rule is: **unknown calibration limits what TSK claims a value means; it does
not block observation unless being wrong has a meaningful cost.**

## Route model: a Panda bus number is not enough

Every diagnostic route has two independent dimensions:

```text
Panda logical bus + ELM327 safety parameter -> physical vehicle path
```

For logical bus 1, Panda uses MCU FDCAN2. In ELM327 safety mode:

| ELM parameter | FDCAN2 semantic path |
|---:|---|
| `1` / non-zero | normal harness |
| `0` | OBD-II mux |

The tooling therefore treats a route as at least:

```text
(elm327_param, tx_bus, rx_bus, request_id, response_id, F181)
```

Initial discovery always tries **normal-harness routing (`param=1`) first**, probes
logical buses in `1, 0, 2` order, reads F181, and requires an `8965...` EPS identity.
Duplicate routes carrying the **same** F181 are retained as alternates (bus 0/2 can see
the same electrical network with the relay in pass-through), while distinct `8965...`
identities under one physical routing state fail closed rather than being guessed apart.
OBD routing (`param=0`) is an explicit fallback.

Once a stateful operation starts, the selected physical route is preserved. A later
rediscovery does not silently change ELM parameters. This is important on Toyota-B:
changing only `UdsClient.bus` while leaving ELM327 at implicit parameter 0 does **not**
reproduce a physical CAN0/CAN1 repin. The direct stock-wire diagnostic route is
normal-harness `param=1` with logical bus 1/FDCAN2. Span's exact `8965F1208000` specimen
has now dynamically confirmed that route through PROGRAMMING, seed request, accepted boot
SecurityAccess key, and complete CodeFlash/DataFlash/local/global-RAM acquisition. That
confirms the route for that specimen; it is not evidence that every Toyota-B target maps
or transitions identically, and it still does not reproduce the CAN0/CAN2 intercept-relay
topology of a physical repin.

## Programming handoff semantics

The analyzed Sienna `8965B4512000` application proves that its first `10 02`
PROGRAMMING request is an **asynchronous reset handoff**, not a request that must return a
final `50 02` before the application disappears.

For that calibration:

- DEFAULT -> PROGRAMMING is not the valid application transition; use
  DEFAULT -> EXTENDED -> PROGRAMMING.
- an explicit NRC remains a real rejection;
- NRC `0x88` is the vehicle-speed guard;
- NRC `0x22` can represent the recovered application handoff prerequisites;
- after the handoff succeeds, shutdown/reset can overtake the final positive response;
- application and bootloader diagnostics remain on the same EPS CAN controller;
- physical request `0x7A1`, response `0x7A9`, and functional request `0x777` are
  firmware-verified for `8965B4512000`.

`tsk/lib/programming.py` implements the shared discriminator used by the extractor,
DataFlash dumper, and programming probe: preserve the route, issue one controlled
handoff, record `panda.health()` and `panda.can_health(bus)`, and require the diagnostic
endpoint to reappear on that route. A response timeout alone is not classified as
failure.

## Boot bootstrap, exact ciphertext, and application-retained runtime are separate gates

A successful PROGRAMMING handoff proves only that the endpoint transitioned. It does not
by itself prove any of the following:

1. the bootloader's authenticated `RequestDownload`/`0x10F0`/`0xFF00` contract;
2. acceptance of a particular encrypted 4 KiB payload fixture; or
3. that downloaded RAM survives application initialization as executable memory.

TSK now models those as independent evidence axes instead of one coarse “RAM-exec
compatible” bit.

### 1. Authenticated-RAM boot geometry / bootstrap family

`tsk/lib/ram_exec_geometry.py` and `tsk/lib/bootstrap_profile.py` resolve exact F181s; there
is still **no prefix rule**. Cross-vehicle evidence now covers the shared
`f05f36b7d78c03e24ab4faef2a57d044` boot SecurityAccess family, zero `0201/0202`,
`FEBF0000 + 0x1000`, `0x10F0`, and `0xFF00` on these exact Toyota/Denso EPS software IDs:

| exact F181 | boot geometry | evidence grade |
|---|---|---|
| `8965B4512000` | `FEBF0000 + 0x1000`, callback `FEBF0000` | local firmware-static + generated-artifact verified |
| `8965H1202000` | same bootstrap architecture | observed owner-side target-built range-payload execution + recovered CodeFlash |
| `8965F1208000` | same bootstrap architecture | observed Span target-built range-payload execution + recovered CodeFlash |
| `8965F3307000` | `FEBF0000 + 0x1000`, callback `FEBF0000` | maintainer 2026 Camry: live SecurityAccess/download/`0x10F0`/`0xFF00`/range-payload execution + exact CodeFlash gate verification |
| `8965B4209000` | same | external-source / field-supported bootstrap family |
| `8965B4233100` | same | external-source / field-supported bootstrap family |
| `8965B4509100` | same | external-source / field-supported bootstrap family |
| `8965B4514000` | same bootstrap family | external-source partner payload/DataFlash workflow |
| `8965F3401200` | same bootstrap structure | external-source blurbdust patcher, dual CPU |
| `8965F4207000` | same bootstrap structure | external-source blurbdust patcher |
| `8965F4201000` | same bootstrap structure | external-source blurbdust patcher |

The newer-Toyota `FEBE0000` shellcode report remains only a linker-VMA observation. It is
not promoted to authenticated download geometry, callback geometry, or application-retained
runtime geometry.

### 2. Exact encrypted-fixture acceptance

Shared boot geometry does **not** mean every committed ciphertext transfers. TSK now checks
the selected payload SHA independently before any production DataFlash WDBI/download:

| fixture | SHA-256 | exact-F181 evidence used by TSK |
|---|---|---|
| public RAM key-table payload | `d972d4bf432685217591768600a9abd7820d35b04a72270edc87074365356be2` | exact repository fixture pinned only on `B4512000`; other family rows require target-specific fixture evidence |
| standard 32 KiB DataFlash payload | `d48988366b5e6d2ddd7438caca5e6f6f02daba9b650263c323a2ffd770a06e34` | locally verified `B4512000`; exact `F3307000` Camry gate/root/geometry plus live authenticated range-payload execution |
| auto-reset DataFlash derivative | `bf62449f85648ea24708961749bf53f75f36083c01bcf54114d567da0e178725` | locally rebuilt/verified `B4512000` gate only; still blocked on `F3307000` |
| Camry 0..2 MiB CodeFlash range reader | `860f8a3418d23ccfd0861a97efdb9e1d23a8854c3a629b8d7b6821eb93d0b588` | exact `F3307000` field acceptance; successful 524288/524288-word acquisition |

For every other bootstrap-family row — including the observed `H1202000`/`F1208000`
Corollas and the historical B4/F3/F4 targets — TSK does not invent an exact local fixture
mapping. A target-accepted fixture must be supplied with an explicit SHA/evidence record,
and the target's own `0x10F0` remains the live discriminator. `F3307000` is the deliberate
exception for the standard DataFlash fixture because its exact CodeFlash reproduces the
payload-build root and byte-identical download/decrypt/CRC-CMAC/callback gate, after the
same car had already executed an authenticated 4 KiB range payload through that geometry.

The production DataFlash dumper therefore resolves **both** boot geometry and selected
fixture identity before PROGRAMMING, SecurityAccess, DID writes, RequestDownload, or
payload transfer. The instrumented diagnostic may still observe PROGRAMMING, bootloader
identity, and `REQUEST_SEED`; even after a family-supported SecurityAccess result it stops
before WDBI/download when the exact DataFlash ciphertext is not evidenced.

The exact Camry CodeFlash collector is a separate retained acquisition tool, not a generic
family operation. `tsk/tools/dump_codeflash.py` requires exact
`8965F3307000 / 8A3113303100`, exact `(bus1,param1,0x7A1->0x7A9)`, source-real
`0x51E Ready=0`, the exact `860f...` payload, and the verified old-stack bootstrap before
PROGRAMMING. It persists a one-byte-per-word coverage bitmap, detects conflicting overlap,
can resume a partial pass, tolerates recoverable Panda SPI NACKs, and verifies the known
2 MiB raw / 1 MiB normalized hashes on completion.

The legacy RAM key-table extractor remains narrower than the bootstrap family because its
CPU-visible `FEBE6E34` key-table layout applies only to older B4 evidence. The current
production gate is stricter: the repository `d972...` ciphertext is exact-fixture-pinned
only for `8965B4512000`, whose application does not maintain that legacy key table. The
older extractor therefore fails closed until a target-accepted payload fixture is supplied
rather than projecting one Sienna ciphertext across the B4 family.

### 3. SHA-bound application-retained ephemeral runtime

The callback-free scheduler bridge is a different contract again. Offline analysis must
start from an exact 1 MiB CodeFlash image and produce a
`p1me-ephemeral-runtime-target-manifest-v1` that proves the target's application startup,
scheduler/SecOC/COM anchors **and** SHA-bound retained application R/W/X geometry. TSK
validates that manifest together with the audited inert canary in
`tsk/lib/ephemeral_runtime.py`.

The built-in **scheduler-canary package** currently covers only `8965B4512000`:

```text
CodeFlash SHA-256  21140bbd65e530a9e518a3e84e20e5d85679675bc09cc724cb177bb7c76bafde
manifest SHA-256   e0fddd8204ec9ec34b6cdf88d3b34f24097cef9609d7471f50c181b8ef626395
retained R/W/X     FEBF0000..FEBF0307  (0x308 bytes)
callback cell      FEBF0FD0
heartbeat          FEBFFBF0
inert canary       332 bytes
canary SHA-256     81176c6e1c33451cfa63bd3b4a0e07b8b0fb952c70b3d67442f1a294ed6b651e
```

TSK also bundles the exact resolver manifests for `8965H1202000` and `8965F1208000` as
read-only regression evidence. Both resolve the foreign image semantics but report
`semantic-resolved-steering-unsupported`, three SecOC records with classic `0x2E4/0x131`
missing, and unresolved image-bound retained-RWX geometry. They are displayed as evidence
on the runtime page but **cannot** satisfy the executable package gate.

Exact F33 is different again. Field startup proves the low `FEBF0000` boot staging pocket
is overwritten by the stock application, while `FEBFF9F0..FEBFFBFB` is a 524-byte
executable tail that survives startup byte-for-byte. Exact application XCP code admits
writes across `FEBF7C00..FEBFFBFF`, but the observed normal `(bus1,param1)` CONNECT timed
out and no reversible application-context control-transfer object into that tail has been
recovered. TSK therefore records F33 placement evidence without presenting it as a deployable
runtime package.

The host-side bootstrap constructor now models both recovered Denso protocol axes used by
the RE live installer: old/new routine magic (`45 00` / `45 01`) and CPU0/CPU1 memory-ID
plus DID-`0203` geometry. This does not broaden live authority. The built-in canary path is
still explicitly pinned to old-stack/CPU0 B4512000 and preserves its already-reviewed
five-zero-byte DID-`0203` request; the generic CPU0 `01 00 00 00 00` convention and the
other constructor values are request-planning support for a future exact target with its
own evidence.

`/ephemeral-runtime.html` can import a complete foreign **executable** package only when it
contains a runtime-build-ready resolver manifest, its matching audited inert canary, and the
required exact image bindings. Live arbitrary-RAM substitution additionally requires
target-specific proof of the post-`0x10F0` short-chunk primitive; cross-vehicle bootstrap
reuse does not imply that memory-safety bug. At present TSK enables the live canary only on
the exact `B4512000` CodeFlash where MEM-SAFE-001 is verified.

The live operation is intentionally **canary-only**: it authenticates the known bootstrap,
substitutes the audited 332-byte inert scheduler, writes `FEBF0FD0` last, triggers the
existing `0xFF00` callback path, proves the application heartbeat advances, then hard-resets
the EPS and proves the heartbeat stops. It requires explicit isolated-bench acknowledgement.
TSK ships **no steering-bridge binary and no bridge-deployment endpoint** in this change.

The historical "dormant `ToyotaEphemeralSecOCBridge` openpilot mode" is **superseded and
removed**: openpilot no longer carries any private bridge/lateral parameters, oracle
capture, or `ALLOW_DEBUG` development safety mode. The exact-F33 Camry instead uses the
ordinary Toyota/openpilot port shape on `TOYOTA_CAMRY_TSS3` — normal CarParams,
CarController, and Panda safety with a `TSS3` flag — whose B6 sender marks only its own
generated `0x0B6` frame with an all-zero MAC28 and live freshness. That frame is accepted
because this maintainer EPS carries the persistent Gate-2 patch; no key and no RAM bridge
are involved. See [`OPENPILOT_TARGET_INTEGRATION.md`](OPENPILOT_TARGET_INTEGRATION.md).

## SecurityAccess domains are separate

Do not use “the Sienna secret” without naming the domain. Static analysis recovered two
independent SecurityAccess implementations on `8965B4512000`:

| Context | UDS pair | Secret |
|---|---|---|
| bootloader | `27 01` / `27 02` | `f05f36b7d78c03e24ab4faef2a57d044` |
| application | `27 03` / `27 04` | `893e08418c741ffa2a9c044bffa55813` |

The recovered boot failure policy is bounded and volatile: the first bad `27 02` returns
NRC `0x35`; the second bad key returns `0x36` and starts an approximately 10-second RAM-only
delay; a `27 01` seed request during that window returns `0x37`. No NVRAM/permanent boot
SecurityAccess lockout is recovered. Runtime tooling therefore waits/retries only when
`0x37` is actually returned rather than imposing an unconditional delay.

Both use the same two-stage AES construction with a tester-controlled 16-byte data record,
but they are different security domains. The historical Corolla `sendkey_probe` used the
bootloader `01/02` secret against an application `03/04` challenge; its resulting NRC
`0x35` therefore did not establish that Corolla rejected the corresponding Sienna
application secret.

The application root is no longer secret on the three tracked images. KEYLESS-006 proves
that normal startup mirrors the 16-byte root into pre-auth readable LocalRAM: `FEBF7BE0`
on `8965B4512000`, and `FEBF7B80` on `8965H1202000` / `8965F1208000`. The Application
memory disclosure page now identifies exact F181 first and, only for those three targets,
reads that mirror with extended-session SID `0x23` / ALFID `0x15` / memory ID 1. It sends
no SecurityAccess key or write and verifies the recovered bytes against the firmware-pinned
`893e08418c741ffa2a9c044bffa55813` root. This does **not** disclose or bypass the
independent bootloader `01/02` root.

The Application SecurityAccess comparison page therefore remains a deliberately separate
counted operation. It still reads F181 first and **will not send a cross-calibration key
unless the operator explicitly arms one attempt**; on an exact KEYLESS-006 target, use the
read-only recovery path first instead of guessing the application credential.

## Key trust boundary

A checksum-valid memory structure is only a candidate on an unknown calibration.
Closely related EPS variants do not share one CPU-visible key-storage architecture: the
old RAM key-table technique works on some `8965B4x` siblings, while static analysis of
`8965B4512000` shows that its corresponding `FEBE6E**` region is not a firmware-maintained
key-slot mirror.

Accordingly, `/api/extract` and `/api/match` now have a staged trust boundary:

1. a persisted SecOC CAN oracle must contain enough **usable** synchronization plus
   known/discovered protected samples (classic and pinned FD profiles) before a programming/extraction attempt;
2. the RAM or DataFlash path may recover a candidate key;
3. the candidate is independently AES-CMAC verified against the persisted target oracle;
4. a verified key is stored privately as **recovered evidence**, outside downloadable
   evidence bundles; it is **not** written as `SecOCKey`;
5. TSK builds an evidence-bound target profile containing identity, physical route,
   observed buses/IDs/DLC/rates, per-stream cryptographic matches, and compatibility with
   the current Toyota openpilot sender;
6. every target-specific openpilot field (DBC, complete safetyParam, steering mode, EPS
   scale, lateral command/status role, explicit longitudinal-control mode/topology) must
   be filled with an evidence source and reviewed for that exact profile ID;
7. the checked-out `opendbc_repo` must then pass the source audit for the exact platform,
   EPS F181, DBC, steering mode, EPS scale, longitudinal ownership, and derived safetyParam;
8. a normalized stationary/bench session must prove stationary state, a signed
   zero-actuation command on a target-verified stream, EPS acceptance/status feedback,
   and no new fault latch;
9. only then can `/api/install-recovered-key` copy the private recovered key into the
   existing `SecOCKey` interface.

A failed cryptographic verification never persists or installs the candidate. A key that
authenticates an unfamiliar target stream is no longer rejected merely because it does
not authenticate `0x131/0x2E4`; those IDs are compatibility evidence, not target identity.
The raw recovered key lives under `/cache/tsk/private/` and is deliberately excluded from
TSK evidence bundles; the shareable profile carries only a key fingerprint and match
counts.

The offline DataFlash matcher requires at least 30 authenticated samples and a real
cryptographic domain: at least two matching synchronization samples **or** at least two
matching protected samples. It still requires observed synchronization traffic to
reconstruct protected freshness, but the candidate key itself need not authenticate
`0x00F`. This intentionally supports calibrations with separate sync and protected keys.
If several real key domains are present in the same DataFlash dump, the matcher prefers a
candidate compatible with the current lateral sender when one exists, while still
retaining different verified domains for a target whose protected surface differs.

For reference, current Toyota `CarController` signs `0x2E4` (`STEERING_LKA`) and `0x131`
(`STEERING_LTA_2`) for lateral control; with openpilot longitudinal enabled it also signs
`0x183` (`ACC_CONTROL_2`). TSK reports lateral and longitudinal compatibility separately.
None of those IDs is treated as the discovery boundary for an unknown Camry/TSS3 target.

Partial DataFlash retention is also cross-calibration-safe now. A partial is no longer
thrown away merely because it missed the historical `0xFF206E14` Sienna/Yaris window.
Any capture with at least one contiguous 16-byte region is saved together with a
byte-coverage mask, and the matcher scans only fully received candidate windows. The
historical `0x6E14` offset remains an annotation/targeted diagnostic, not a trust gate.

## Application SID 0x23 request grammar

Recent firmware-static recovery corrected an important assumption in the original TSK
read-memory probe. Sienna `8965B4512000` does expose application ReadMemoryByAddress in
EXTENDED session without SecurityAccess, but its accepted request is not the ordinary
ALFID `0x14` form emitted by `UdsClient.read_memory_by_address()`. The exact request is:

```text
23 15 <memory-id> <absolute-address:4-byte-be> <size:1-byte>
```

Memory ID `1` selects `FEBE0000..FEBFFFFF` LocalRAM and memory ID `2` selects
`FF200000..FF207FFF` DataFlash, subject to firmware exclusion intervals. The application
can therefore disclose 107,924 LocalRAM bytes and 29,952 DataFlash bytes on this exact
calibration. The historical object-15 address `FF206E14` is intentionally protected, but
`FEBF2D08..FEBF2D17` is readable; that LocalRAM range is the bootloader DID `0x0201`
payload-key-derivation input buffer, making post-handoff residue a concrete dynamic
question.

`read-mem.html` now tries the exact memory-ID grammar first and keeps one ordinary
ALFID-`0x14` comparison for unknown calibrations. A negative result therefore no longer
means “Sienna blocks SID 0x23”; it means the tested target did not answer either bounded
read shape.

## Application XCP observation surface

Sienna `8965B4512000` also configures an unauthenticated XCP-shaped application channel on
CAN `0x7F7/0x7F8`. CONNECT is sufficient to establish protocol state; standard
SHORT_UPLOAD `0xF4` can read permitted LocalRAM directly, and the configured DAQ subset
can sample up to 28 one-byte LocalRAM sources per list into `0x7F8` DTOs. The TSK XCP
observer uses this as an instrumentation path for unresolved dynamic questions such as the
d/q actuation discriminator and lifecycle/control-state transitions.

The field tool is deliberately narrower than the recovered firmware capability:

- after a positive CONNECT, bounded F4 reads are allowed on unknown F181s;
- temporary DAQ configuration is also allowed cross-calibration, but only for addresses
  that first returned data through F4, and STOP is attempted after a successful start;
- the profile descriptions and address meanings are firmware-verified only on exact
  `8965B4512000`; on another F181 the same addresses are raw observation candidates;
- only `FF`, `F4`, `E3`, `E2`, `E1`, `E0`, and `DE` are implemented;
- XCP page copy, SET_MTA, generic UPLOAD, DOWNLOAD, MODIFY_BITS, and source-memory writes
  are not exposed by TSK.

The recovered 32 KiB XCP write window is a real firmware primitive but has no recovered
executable, persistent, or motor consumer. It remains research evidence rather than a live
field-tool feature.

## SecOC capture and matcher profile

Passive capture remains unfiltered: every non-echo CAN payload on every observed bus is
persisted for the full observation window. The target profile additionally materializes a
full `(bus, arbitration ID, DLC)` inventory with sample counts and observed cadence, so
CAN-FD widths and unknown non-classic streams do not remain trapped only in raw NDJSON.
Known IDs are annotations/hypotheses, not capture filters or an early-stop gate.

The current known classic family remains:

```text
sync hypothesis: 0x00F
known protected: 0x116 0x131 0x132 0x177 0x183 0x24D 0x283 0x2E4 0x344
```

But the matcher no longer stops there. After each `0x00F` state on the same run/bus, every
8-byte stream is evaluated for the classic Toyota trailer structure: reset-low-bit
agreement, message-counter-low2 variation, and authenticator variation. Strong unknown
streams are admitted into the cryptographic scan; structural classification alone never
makes them trusted. A regression fixture proves that an unknown protected ID with a key
separate from the synchronization key remains discoverable through the complete
DataFlash first pass.

Verification is bus-aware and reports matches per CAN ID, per bus, and per `(bus, ID)`
stream. Firmware recovery now pins `0x132` as a normal classic protected receive profile
on `8965B4512000`, so it joins the classic cryptographic matcher. The same image pins
`0x090` and `0x0D7` as 32-byte secured CAN-FD profiles with authenticated input
`DataID_be16 || payload[28] || freshness[6]` and the same 4-bit transmitted freshness +
28-bit CMAC trailer. TSK therefore verifies those two FD streams cryptographically when
observed with same-bus synchronization context. Physical DLC 48/64 aliases are reduced to
the first 32 bytes for the EPS authenticated view, matching the recovered clamp; unknown
larger frames are never reinterpreted as classic candidates.

These additions remain calibration-scoped evidence rather than target ownership claims.
For the analyzed Sienna, `0x2E4` and `0x131` are the two recovered steering-command modes,
`0x132` has a bounded snapshot-only downstream role, `0x090` carries protected rear-wheel
speed / steering-angle-speed information, and `0x0D7` carries protected vehicle-speed and
validity/status information. An unfamiliar target must still prove its own receive/control
roles before openpilot integration is enabled.

Receiver freshness is also now bounded more tightly. The analyzed application clears its
SecOC receive windows at initialization and accepts any authenticated forward sync
trip/reset jump without a maximum delta. Failed MAC verification does not advance
freshness. The recovered retry budget is **per queued PDU**: an ordinary bad-MAC PDU gets
one retry of that same queued message, then admission of the next fresh PDU resets the
counter. Distinct newly queued bad frames are therefore not subject to a recovered
persistent/per-source throttle. That creates reset-window,
future-sync, and theoretical 28-bit online-guess avenues, but their practical timing,
throughput, suppression, and recovery behavior are still dynamic. TSK does not inject
replay/future-sync/tag-guess trials automatically; those remain isolated-bench experiments.

## Recommended field workflow

1. **EPS fingerprint and route map** — identify F181 and record the complete physical
   route, not merely a Panda bus number.
2. **Passive CAN inventory** — observe arbitration IDs, buses, frame widths, and CAN-FD
   presence with normal-harness routing selected.
3. **Full READY target-profile capture** — retain the entire observation window and let
   structural discovery surface unknown classic SecOC candidates.
4. **Not Ready to Drive characterization** — run the resumable UDS sweep and read-only
   probes. Use the corrected memory-ID SID `0x23` probe for application disclosure and the
   XCP observer for `0x7F7/0x7F8` reachability; exact-Sienna F4/DAQ can instrument selected
   LocalRAM state without invoking the state-changing diagnostic operations. Stateful
   subfunctions remain separated from observation-oriented work.
5. **Programming handoff probe** — if key recovery requires it, perform one
   route-preserving handoff and inspect endpoint reappearance plus Panda/CAN health.
6. **Bootstrap-family and boot geometry** — bind the exact F181 to evidenced
   SecurityAccess/DID/RequestDownload/`0x10F0`/callback behavior. Keep this separate from
   application-retention claims.
7. **Exact payload fixture** — prove the specific encrypted 4 KiB ciphertext selected for
   this operation. Shared `FEBF0000` geometry alone does not authorize a DataFlash payload.
8. **Optional exact CodeFlash / ephemeral-runtime research** — on exact F3307000, the
   retained NRTD collector can reacquire the known 2 MiB transport range and normalized
   1 MiB image. For a callback-free route, run the semantic resolver and import its SHA-bound target manifest,
   and execute only the inert canary on an isolated bench. A foreign target additionally
   needs its own post-auth substitution evidence. The inert canary stays bench-only research;
   no steering-resident deployment exists in TSK, and the F33 port does not depend on one.
9. **Cryptographic key recovery** — when a readable key route exists, verify the candidate
   against the discovered target streams and persist it privately; do not install it yet.
10. **Target integration review** — fill every openpilot/DBC/safety/control field with an
    explicit evidence source in `target-profile.html`.
11. **opendbc implementation audit** — implement the exact target/F181 in `opendbc_repo`,
    then use **Re-audit opendbc** to prove source agreement with the reviewed profile. See
    [`OPENPILOT_TARGET_INTEGRATION.md`](OPENPILOT_TARGET_INTEGRATION.md).
12. **Stationary/bench acceptance** — capture a zero-actuation signed-command session and
    validate target-specific status feedback plus before/after fault state.
13. **Operational install (key-backed targets only)** — only after the profile-bound gates
    pass, install the already recovered key through `/api/install-recovered-key`. This path
    never masquerades as a key and is irrelevant to the keyless exact-F33 port, whose gate is
    the stationary validation ladder.

## DataFlash payload variants

The standard 32 KiB DataFlash payload remains the default. It is **not** a generic
cross-calibration shellcode blob: TSK requires both compatible authenticated boot geometry
and exact-F181 evidence for this ciphertext. `FEBF0000/0x1000` by itself is insufficient.

```text
SHA-256 d48988366b5e6d2ddd7438caca5e6f6f02daba9b650263c323a2ffd770a06e34
```

An optional experimental **local derivative** is also included:

```text
SHA-256 bf62449f85648ea24708961749bf53f75f36083c01bcf54114d567da0e178725
```

Its executable body comes from Vance's external `candidate-f05` artifact, whose static
byte/control-flow analysis recovered the same sequential `0xFF200000..0xFF207FFF` dump
followed by a boot-reset call to `0x157E` instead of the standard payload's terminal
infinite loop. The original Vance ciphertext (`296d87d2...`) was built under the
bootloader SecurityAccess secret rather than the analyzed Sienna's normal
`PAYLOAD_BUILD_SECRET`, and explicitly fails the normal payload gate. **TSKM never sends
that raw external ciphertext.**

The included derivative preserves candidate-f05's verified RH850 body and CRC region
byte-for-byte, recomputes the CMAC under the normal payload-build derived key, and
re-encrypts it with the normal zero-DID201/zero-IV payload scheme. The derivative's body
SHA-256 remains `5551b5aaecaeb361b21777d2f91d7cdf7b2dfe6b2ec0d1356d544cdbdf3416d1`.
It is hash-pinned and unit-tested here, but vehicle execution of the reset-ending variant
has not been independently confirmed. `tsk/tools/build_autoreset_payload.py` reproduces
the committed derivative from the analyzed CodeFlash plus the pinned raw candidate and
fails closed on every source/body/output hash. The UI exposes the derivative only through
an explicit **experimental auto-reset** checkbox; it is never selected implicitly.

## Durable evidence

Field transcripts are append-only under `/cache/tsk/` until an AGNOS update or manual
deletion. The bundle endpoint is:

```text
/api/evidence-bundle
```

The `.tar.gz` contains `session-manifest.json`, operation history, raw NDJSON captures,
UDS transcripts, DataFlash binaries, exact-target CodeFlash binaries/coverage metadata,
payload hashes, SHA-bound ephemeral-runtime package/
validation artifacts, job states, route metadata, programming-handoff health telemetry,
and device logs. The manifest records the openpilot
branch/commit and a hash prefix rather than the plaintext dongle ID.

## Local verification

```bash
PYTHONPATH=opendbc_repo:panda uv run python -m unittest discover -s tsk/tests -v
PYTHONPATH=opendbc_repo:panda uv run python -m compileall -q tsk
bash -n launch_chffrplus.sh
git diff --check
```
