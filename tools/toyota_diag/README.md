# Toyota diagnostics CLI

`tools/toyota` is the single Comma-side entry point for Toyota diagnostics recovered from Techstream/GTS+. The bundled `camry-2026-f33` registry is a generated, derived artifact: it contains ECU names/addresses, GTS DID/DTC catalogs, static Active-Test plans, the exact F33 identity guard, and the live-validated DTC-clear route. The CLI also bundles clean generated metadata for the current GTS+ TSS3 Operation/Image FFD protocols and PCS Data Viewer recorder schema. It does **not** contain Toyota DLL/DDB/EXE binaries.

Offline discovery works without Panda access. The CLI is ECU-first now, so you can browse by Toyota names instead of memorizing DIDs or command families:

```bash
./tools/toyota search LTA
./tools/toyota ecu list
./tools/toyota ecu frc
./tools/toyota frc                         # shorthand for `ecu frc`
./tools/toyota ecu frc data "LTA Control"
./tools/toyota frc data "LTA Control"      # shorthand keeps ECU context
./tools/toyota frc monitor "LTA Control"      # live ECU-first shorthand
./tools/toyota frc read 0x1601                 # shorthand for `did read frc ...`
./tools/toyota ecu frc dtcs U0131
./tools/toyota ecu frc active-tests
./tools/toyota ecu frc plugins
./tools/toyota utility list
./tools/toyota utility plan single_routine_active_test
./tools/toyota vehicle
./tools/toyota vehicle list
./tools/toyota can topology
./tools/toyota did decode eps 0x1037 0001
./tools/toyota active-test plan frc 0xA429
./tools/toyota active-test plan frc 0xA429 --json
./tools/toyota search "Arbitration result Lateral ID"
./tools/toyota ffd data "pinion angle"
./tools/toyota ffd robs "Hands Free"
```

`search` spans ECU/category names, Data List signals, DTCs, Active Tests, v4 function/plugin bindings, recovered generic utility-family metadata, and the separate PCS Data Viewer TSS3 Operation-FFD signal/trigger namespace. This matters because recorder-only Toyota names such as `Arbitration result_lateral ID` (`0x5285`) and `Arbitration result Pinion angle` (`0x57DE`) do not exist in the ordinary P5 Data Monitor DDB. `ecu ... functions` shows the recovered type-26/27 function/detail hierarchy even where Toyota's function names remain unrecovered; `ecu ... plugins` shows the role → DLL binding and only labels semantic kinds recovered for the exact plugin identity. Offline catalog browsing (`ecu list/info/functions/plugins/data/dtcs/active-tests`, `did list`, and `dtc catalog/decode`) accepts `--json`, matching the machine-readable live/planning surfaces without importing Panda. ECU lookup errors include close-match suggestions. The original verb-first `ecu info`, `did list`, `dtc catalog`, etc. remain supported.

Live commands have two transport modes. If `pandad` is stopped, the CLI takes direct Panda ownership using the exact live-validated Camry ELM327 setup. If `pandad` is already running, the CLI reuses openpilot's `can`/`sendcan` ISO-TP path **only** when the one live Panda is already in ELM327 safety param 1 with `controlsAllowed=false` on the profile's validated bus-0 topology. It never changes a running Panda's safety mode; if openpilot has already transitioned to Toyota/onroad safety, the command fails closed and tells you to stop manager for direct access. `./tools/toyota transport status` checks this gate without transmitting anything.

```bash
./tools/toyota transport status
./tools/toyota can sniff 0xB6 --duration 10
./tools/toyota can sniff 0x30 0x412 --duration 0 --json > can.jsonl
./tools/toyota dtc scan
./tools/toyota dtc scan --json > dtc-snapshot.json
./tools/toyota did read eps 0x1037
./tools/toyota did watch frc 0x1601 0x1501 0x1681 0x1903 --interval 0.25
./tools/toyota monitor frc LTA --changed
./tools/toyota monitor frc 0x1601 0x1914 --jsonl > frc-monitor.jsonl
./tools/toyota monitor frc 0x1601 0x1914 --csv > frc-monitor.csv
./tools/toyota observe tss3-longitudinal --changed
./tools/toyota observe frc:0x1601 brake:0x10A1 --jsonl > joined-monitor.jsonl
./tools/toyota scan
./tools/toyota scan --json > car-snapshot.json
./tools/toyota vehicle detect
./tools/toyota uds raw eps 0x22 F181
./tools/toyota uds raw 0x763 0x22 1033       # read-only unregistered endpoint
```

Read-only `uds raw` also accepts an explicit unregistered 11-bit request address,
which is useful for recovered Toyota utility endpoints such as the MACKey-registration
master `0x763` that are not asserted as installed vehicle-profile ECUs. Mutation to an
unregistered address remains forbidden even with `--force`; add a registry identity
guard before any write/session/routine use.

## TSS3 Operation/Image FFD

Current GTS+ exposes two proprietary recorder surfaces on `FRC_P5 = Front Recognition Camera 2`. Both are now first-class, read-only CLI surfaces rather than opaque plugin rows. The exact F33 vehicle was used to validate both protocols.

Operation FFD is the highest-value control/arbitration recorder. `AB11` enumerates behavior/RoB codes, `AB12 <behavior_be16>` enumerates stored record IDs, and `AB13 <behavior_be16> <record_be16>` returns the recorder blocks. The CLI decodes those blocks with the recovered PCS Data Viewer schema (`physical = raw * Lsb + Offset`, including signed fixed-point and IEEE float fields):

```bash
./tools/toyota ffd operation list
./tools/toyota ffd operation records 2818
./tools/toyota ffd operation read 2818 0100
./tools/toyota ffd operation read 2818 0100 --query pinion
./tools/toyota frc ffd operation read 2818 0100 --query LTA --json
```

Recorder IDs are hexadecimal by Toyota convention even when they contain only decimal digits, so `2818`, `0100`, and `0201` are interpreted as hex without requiring `0x`. Global `search`, `ffd data`, and `ffd robs` are offline and do not touch Panda. Useful recovered steering joins include generic TSS request `0x5282`, LDA `0x5531`, LTA `0x5631`, arbitration-result lateral ID `0x5285`, arbitration-result pinion angle `0x57DE`, EPS pinion state `0x560D`, and active-steering state `0x5265`.

Image FFD uses the live-validated current P5 path: extended diagnostic session, SecurityAccess `27 03/04` with the recovered six-byte level-49 algorithm, then `AB31` RoB enumeration and `AB33 <rob_be16> <frame_be32>` split-record fetches. The host key algorithm is release-local and contains no vehicle/package secret; the CLI still applies the exact vehicle identity guard and restores default session on exit.

```bash
./tools/toyota ffd image info
./tools/toyota ffd image list
./tools/toyota ffd image read 2822 0201
./tools/toyota ffd image read 2822 0201 --json
```

For the exact Camry live witness, frame `0201` is split 1 / data set 1 / trigger 1. `image read` deliberately exposes the EB33 block inventory and split `0x6002..0x6017` payloads; it does not silently synthesize/decrypt/write a JPEG. PCS Data Viewer semantics for split reassembly and the `0x2081 != 01` byte transform remain preserved in the bundled metadata for a future explicit export command.

`monitor` is the human-facing Data List view: broad signal-name terms expand to matching DIDs, signals sharing a DID are coalesced, interactive terminals redraw a compact value table, and `--changed` suppresses unchanged rows. Under registry v4 it also uses the recovered current-P5 `DiagnosticSession` lifecycle for wire-proven categories: inspect/poll F186, D1 `10 01` → D2 `10 03` when needed, periodic `22 F1 86` session polling, and deterministic D1 cleanup. Categories outside the registry's `wire_proven_categories` stay on the conservative default-session read path rather than inheriting an unproven lifecycle. `--jsonl` emits one structured sample group per line and `--csv` emits one row per decoded signal sample.

`observe` extends the same read-only monitor machinery across multiple ECUs. Each argument is `ECU:DID_OR_TERM`; the renderer adds an ECU column only when needed and `--changed` keys state by ECU+DID+signal so identically named signals cannot collide. The built-in `tss3-longitudinal` preset captures the current recovered request/source-sink join in one sample group: FRC `0x1B03..0x1B07` plus Brake `0x10A1..0x10A4`. Those Brake values are the Toyota-named upper/lower request acceleration and request IDs "from Toyota Safety Sense"; the FRC values are the corresponding request-side ISA upper-limit state. This preset is an observation convenience, not an assertion that either ECU owns final arbitration or the protected wire publisher.

`scan` produces a read-only vehicle inventory with responding ECUs, F181/F18C/0105 identity reads where supported, DTC status, active-fault summaries, transport state, and profile identity.

The exact Camry maintenance clear is now:

```bash
./tools/toyota dtc clear
```

It verifies EPS F181 contains `8965F3307000`, scans the exact 17-address post-repin set, attempts physical `14 FF FF FF` on responding ECUs, sends the validated functional `0x7DF` Mode 04 frame, then rescans and fails if any `status & 0xAF` fault bits remain.

Raw/functional requests that are not in the explicit read-only allowlist require `--force` **and** the same vehicle identity guard. Unknown/proprietary service IDs therefore fail closed rather than being assumed harmless.

Registry v4 separates **static geometry** from **runtime authorization**. Its 428 Active-Test candidates contain 41 rows whose fixed request geometry is complete, 361 plan-only rows, and 26 unresolved rows. The Comma runtime is stricter again: `executor.py` rejects placeholder identifiers (for example a recovered `0xFFFF` RID), requires complete wire geometry, and for extended-session operations requires the target category to be inside `session_control.wire_proven_categories`. With the current F33 registry that reduces the 41 geometry-complete rows to **14 runtime-executable** and **27 blocked** (21 Engine + 3 HV Battery lifecycle-unproven rows, plus 3 Brake `RID=0xFFFF` placeholders). Fixed routine controls such as FRC `0xA429` LTA Steering Vibration remain runtime-executable, while all direct `0x2F` tests remain plan-only because their exact runtime payload length is not recovered. v4 also carries the raw Toyota CommSet rows (for example CommSet 1 `receive_timeout=1020`, retry count 1); the runtime exposes those rows but deliberately does not reinterpret the raw timeout as seconds until Techstream's `CheckAndConvertRcvTimeOut` conversion is fully recovered.

Viewing and listing never transmits. `active-test list --json` and `active-test plan --json` expose both the raw registry geometry grade and the stricter runtime execution grade/refusal reasons, so automation does not have to infer executability from the generated catalog alone. Mutation requires the literal `--execute` acknowledgement and the profile identity guard; without `--execute`, `active-test run/stop` is a dry-run. Started operations always attempt their recovered stop/return-control request on exception or Ctrl-C, and context cleanup returns an extended session to D1. Cleanup failures are surfaced separately and produce a nonzero result instead of looking successful.

```bash
./tools/toyota active-test list frc
./tools/toyota active-test list frc --json
./tools/toyota active-test plan frc 0xA429
./tools/toyota active-test plan frc 0xA429 --json
./tools/toyota active-test run frc 0xA429                # dry-run only
./tools/toyota active-test run frc 0xA429 --execute --hold 1
./tools/toyota active-test stop frc 0xA429 --execute
```

`utility list/plan` exposes the ten recovered generic category-0 Techstream utility/plugin families and their generic `0x31`/`0x2F` templates. Registry v4 deliberately does **not** convert those family bindings into concrete per-ECU utility operations, so `utility run` fails closed today. The backend is already generic and will execute future concrete utility rows only when the registry supplies an exact target plan.

Registry v2 added the recovered ordinary-P5 Techstream Data Monitor decoder. `did read` always prints the raw DID value bytes first, then decodes each known signal using the registry-selected `p5-linear-msb0-v1` contract: MSB-first bit numbering, big-endian field assembly, two's-complement signed values, `trunc_toward_zero(raw * Mul / Div) + Offset`, exact decimal precision, and converted-value pattern labels. For example, EPS DID `0x1037` renders raw `0001` as `Steering Angle: 1.5 deg`; FRC DID `0x1601` renders Toyota's LTA/Hands-Off state labels. Unknown decoder kinds or undersized payloads fail closed and leave the raw bytes plus metadata visible.

Registry v3 adds the current Camry-HV GTS CAN Bus Check topology plus tracked EPS/FRC/Brake identity observations. `can topology` shows Toyota's vehicle-network domains (for example Front Camera Module on GTS Bus 1 and EPS/Skid Control on GTS Bus 4 behind Central Gateway); those labels are explicitly **not** Panda bus numbers. `ecu info` shows observed F181/F18C/part identities where available and labels their 2026-08-26 Panda-bus1 route as historical pre-repin evidence. The active diagnostic profile remains post-repin Panda bus0.

`did read` and `did watch` accept multiple DID numbers or GTS names for one ECU and reuse a single UDS client. `--json` on `read` emits one machine-readable snapshot; `--json` on `watch` emits one JSON object per sample group, making the same phone/SSH command useful as a lightweight capture logger without a separate script. `can sniff` is strictly receive-only: with `pandad` running it subscribes to the public `can` service regardless of Panda safety mode, and with `pandad` stopped it reads directly from Panda without changing safety. It can filter multiple addresses and emit JSONL for analysis captures.

Use `--registry FILE` or `--profile PROFILE_NAME` to load another supported derived registry when additional vehicles are added. The loader accepts v1-v4 for backward compatibility. Engineering-value decoding requires explicit decoder metadata; topology/observed identities require the corresponding v3+ fields; execution/session behavior requires explicit v4 lifecycle and operation metadata. Nothing is inferred for older registries.
