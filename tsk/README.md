# TSK Toyota TSS 3 field tooling

This branch is research tooling for determining whether known Toyota/Denso EPS SecOC
recovery paths transfer to another calibration without silently importing Sienna-specific
assumptions. Unknown fingerprints are evidence, not automatic compatibility: the tooling
may probe an unknown target, but stateful transfer paths retain explicit calibration
boundaries and recovered keys are not trusted until they authenticate captured vehicle
traffic.

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
  a visible sequence: identify EPS -> capture READY CAN -> confirm PROGRAMMING when the
  calibration is not already in the established transfer set -> recover key material ->
  cryptographically verify -> install.
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
reproduce a physical CAN0/CAN1 repin. The current high-confidence software-equivalence
candidate for that repin is normal-harness `param=1` with logical bus 1/FDCAN2; vehicle
PROGRAMMING confirmation remains required before calling that correspondence universal.

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

## SecurityAccess domains are separate

Do not use “the Sienna secret” without naming the domain. Static analysis recovered two
independent SecurityAccess implementations on `8965B4512000`:

| Context | UDS pair | Secret |
|---|---|---|
| bootloader | `27 01` / `27 02` | `f05f36b7d78c03e24ab4faef2a57d044` |
| application | `27 03` / `27 04` | `893e08418c741ffa2a9c044bffa55813` |

Both use the same two-stage AES construction with a tester-controlled 16-byte data record,
but they are different security domains. The historical Corolla `sendkey_probe` used the
bootloader `01/02` secret against an application `03/04` challenge; its resulting NRC
`0x35` therefore did not establish that Corolla rejected the corresponding Sienna
application secret.

The current Application SecurityAccess page uses the recovered `8965B4512000`
application `03/04` secret. Because a wrong SEND_KEY is a counted attempt, the tool reads
F181 first and **will not send a cross-calibration key unless the operator explicitly arms
one attempt**.

## Key trust boundary

A checksum-valid memory structure is only a candidate on an unknown calibration.
Closely related EPS variants do not share one CPU-visible key-storage architecture: the
old RAM key-table technique works on some `8965B4x` siblings, while static analysis of
`8965B4512000` shows that its corresponding `FEBE6E**` region is not a firmware-maintained
key-slot mirror.

Accordingly, `/api/extract` now has a hard trust boundary:

1. a persisted SecOC CAN oracle must contain enough **usable** samples before any
   programming/extraction request is sent;
2. the RAM path may recover a checksum-valid `KEY_4` candidate;
3. the candidate is independently AES-CMAC verified against the persisted oracle;
4. generic verification and **openpilot-control-domain verification are separate**;
5. only a candidate with evidence on both current openpilot control streams (`0x131` and
   `0x2E4`) is written as `SecOCKey`.

A failed verification returns the candidate and verification evidence for research but
**does not install it**. Likewise, a candidate that authenticates synchronization plus a
non-control domain such as `0x116/0x24D` is reported as cryptographically real but is not
installed as the controller key.

The offline DataFlash matcher requires at least 30 authenticated samples and a real
cryptographic domain: at least two matching synchronization samples **or** at least two
matching protected samples. It still requires observed synchronization traffic to
reconstruct protected freshness, but the candidate key itself need not authenticate
`0x00F`. This intentionally supports calibrations with separate sync and protected keys.
Automatic `SecOCKey` installation additionally requires at least two matches each on
`0x131` and `0x2E4`, the classic streams the current Toyota openpilot controller signs.
If several real key domains are present in the same DataFlash dump, the matcher prefers a
control-domain-verified candidate even when a sync-only key has more total matches; the
other verified domains are retained as non-key-bearing alternate metadata in the result.

Partial DataFlash retention is also cross-calibration-safe now. A partial is no longer
thrown away merely because it missed the historical `0xFF206E14` Sienna/Yaris window.
Any capture with at least one contiguous 16-byte region is saved together with a
byte-coverage mask, and the matcher scans only fully received candidate windows. The
historical `0x6E14` offset remains an annotation/targeted diagnostic, not a trust gate.

## SecOC capture and matcher profile

Passive capture remains unfiltered: every non-echo CAN payload on every observed bus is
persisted. Known IDs are annotations and matcher inputs, not capture filters.

The classic 8-byte Toyota SecOC matcher now covers the full currently known profile:

```text
sync:      0x00F
protected: 0x116 0x131 0x177 0x183 0x24D 0x283 0x2E4 0x344
```

Verification is bus-aware and reports protected matches per CAN ID and per bus. The
DataFlash first pass is the union of sync-domain and per-ID protected-domain probes, so a
protected key is not discarded merely because another key authenticates `0x00F`. This is
important for Corolla evidence: genuine bus-1 `0x116`/`0x24D` traffic must not be reduced
to “0 protected” merely because an older Sienna-specific verifier watched only
`0x131/0x2E4/0x344` on buses 0/2.

Additional Sienna firmware-derived protected IDs such as `0x090`, `0x0D7`, and `0x132`
remain passive-capture annotations; they are not fed into the classic 8-byte verifier
without an independently pinned sender format.

## Recommended field workflow

1. **EPS fingerprint and route map** — identify F181 and record the complete physical
   route, not merely a Panda bus number.
2. **Passive CAN inventory** — observe arbitration IDs, buses, frame widths, and CAN-FD
   presence with normal-harness routing selected.
3. **Passive READY SecOC capture** — collect the synchronization/protected-frame oracle
   before spending a programming/extraction attempt.
4. **Not Ready to Drive characterization** — run the resumable UDS sweep and read-only
   probes. Stateful subfunctions remain separated from observation-oriented work.
5. **Programming handoff probe** — perform one route-preserving handoff and inspect the
   endpoint-reappearance plus Panda/CAN-health evidence.
6. **Transfer hypothesis** — only after the preceding evidence justifies it, run the
   known Sienna-family bootloader/payload or DataFlash path.
7. **Cryptographic verification** — never install a recovered key merely because a RAM
   structure or DataFlash location looks plausible.
8. **Evidence export** — download the bundle before clearing data or moving to the next
   active experiment.

## DataFlash payload variants

The standard 32 KiB DataFlash payload remains the default:

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
UDS transcripts, DataFlash binaries, payload hashes, job states, route metadata,
programming-handoff health telemetry, and device logs. The manifest records the openpilot
branch/commit and a hash prefix rather than the plaintext dongle ID.

## Local verification

```bash
python3 -m unittest discover -s tsk/tests -v
python3 -m compileall -q tsk
bash -n launch_chffrplus.sh
git diff --check
```
