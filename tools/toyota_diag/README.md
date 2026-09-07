# Toyota diagnostics CLI

`tools/toyota` is the single Comma-side entry point for Toyota diagnostics recovered from Techstream/GTS+. The bundled `camry-2026-f33` registry is a generated, derived artifact: it contains Toyota's current vehicle/VIN resolver, install sets and 34 logical mount candidates, Toyota's category+phase transport routes from `CDbProtInfoTable`, literal multi-family support dispatch and live P5/P6 capability metadata, GTS DID/DTC catalogs, static Active-Test plans, exact-F33 identity observations, and the live-validated DTC-clear route. The historical 17-address Camry sweep remains observation data for DTC maintenance; it is not used to admit or route Toyota logical categories. The CLI also bundles clean generated metadata for the current GTS+ TSS3 Operation/Image FFD protocols and PCS Data Viewer recorder schema. It does **not** contain Toyota DLL/DDB/EXE binaries.

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

Live commands have two transport modes. If `pandad` is stopped, the CLI takes direct Panda ownership using Panda's ordinary ELM327 diagnostic safety mode. Direct mode preserves the normal harness routing by default (`ELM327` param 1); `--obd-multiplexing` is an explicit installation-local request to remap logical bus 1 onto the OBD-II pins (`ELM327` param 0). That remap is never inferred from Toyota vehicle/category metadata. If `pandad` is already running, the CLI reuses openpilot's `can`/`sendcan` ISO-TP path when the single live Panda is already in ELM327 safety; the ELM327 safety parameter and `controlsAllowed` state are not additional CLI admission criteria, and `--obd-multiplexing` cannot change a Panda already owned by pandad. It never changes a running Panda's safety mode. If manager has transitioned Panda to an onroad safety model, the managed diagnostic path stops transmitting and directs you to use direct Panda access instead. `./tools/toyota transport status` checks this transport state without transmitting anything.

```bash
./tools/toyota transport status
./tools/toyota --bus 1 --obd-multiplexing transport status  # explicit direct-mode OBD bus-1 remap
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
./tools/toyota vehicle mounted
./tools/toyota did support frc 0x1601 0x1914
./tools/toyota did support 452                  # Toyota category; uses 0x750/0x2A and enumerates advertised DIDs
./tools/toyota --vehicle 12165 did support 6000  # P6 category; uses 0x18DA00F1 normal-fixed addressing
./tools/toyota --vehicle 12165 rid support 6000  # enumerate P6 advertised routine IDs
./tools/toyota uds raw eps 0x22 F181
./tools/toyota uds raw 0x763 0x22 1033       # read-only unregistered 11-bit endpoint
./tools/toyota uds raw 0x18DA00F1 0x22 A100 # read-only 29-bit normal-fixed endpoint
```

`uds raw` accepts explicit 11-bit or 29-bit request addresses, including endpoints that are not part of the selected Toyota profile. This is useful for recovered Toyota utility endpoints such as the MACKey-registration master `0x763` and for normal-fixed P6 routes such as `0x18DA00F1`. Upstream openpilot's UDS transport infers the ordinary 11-bit `+8` or 29-bit source/target-swapped response address; `--rx-address` overrides it when Toyota metadata requires a different physical response. Use `--sub-address` / `--rx-sub-address` for ISO-TP address-extension bytes such as Toyota's logical `0x750` routes. Read-only services transmit directly; a service classified as mutating requires the explicit `--force` acknowledgement, with no separate registry-address or F181 admission check.

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

Image FFD uses the live-validated current P5 path: extended diagnostic session, SecurityAccess `27 03/04` with the recovered six-byte level-49 algorithm, then `AB31` RoB enumeration and `AB33 <rob_be16> <frame_be32>` split-record fetches. The host key algorithm is release-local and contains no vehicle/package secret; the CLI follows that Toyota lifecycle directly and restores default session on exit.

```bash
./tools/toyota ffd image info
./tools/toyota ffd image list
./tools/toyota ffd image read 2822 0201
./tools/toyota ffd image read 2822 0201 --json
```

For the exact Camry live witness, frame `0201` is split 1 / data set 1 / trigger 1. `image read` deliberately exposes the EB33 block inventory and split `0x6002..0x6017` payloads; it does not silently synthesize/decrypt/write a JPEG. PCS Data Viewer semantics for split reassembly and the `0x2081 != 01` byte transform remain preserved in the bundled metadata for a future explicit export command.

`monitor` is the human-facing Data List view: broad signal-name terms expand to matching DIDs, signals sharing a DID are coalesced, interactive terminals redraw a compact value table, and `--changed` suppresses unchanged rows. The default universal bundle carries every Toyota category independently of whether this tool has decoded that category's signal catalog. Support family is Toyota's literal DLL-table selection (`GetSupportP3/P4/P5`, `GetSupportMultiP6`, etc.), not a generation-bit guess or maintained allowlist. Session control is independent again: D1/D2/DD are resolved per category and `DiagnosticSession` follows literal recovered `10 XX` D1/D2 requests when that wire shape is implemented. Unknown lifecycle shapes are an executor-coverage boundary, not a category/generation denial. The older Camry v6 JSON remains only a compatibility/evidence fixture. `--jsonl` emits one structured sample group per line and `--csv` emits one row per decoded signal sample.

`observe` extends the same read-only monitor machinery across multiple ECUs. Each argument is `ECU:DID_OR_TERM`; the renderer adds an ECU column only when needed and `--changed` keys state by ECU+DID+signal so identically named signals cannot collide. The built-in `tss3-longitudinal` preset captures the current recovered request/source-sink join in one sample group: FRC `0x1B03..0x1B07` plus Brake `0x10A1..0x10A4`. Those Brake values are the Toyota-named upper/lower request acceleration and request IDs "from Toyota Safety Sense"; the FRC values are the corresponding request-side ISA upper-limit state. This preset is an observation convenience, not an assertion that either ECU owns final arbitration or the protected wire publisher.

`scan` produces a read-only vehicle inventory over the historical 17-address post-repin DTC sweep, with F181/F18C/0105 identity reads where supported, DTC status, active-fault summaries, transport state, and profile identity. It carries the 34 Toyota logical mount candidates separately with their Toyota-derived routes; DTC-sweep responses are not projected onto those logical categories.

`vehicle detect` obtains the VIN once through openpilot's standard read-only VIN query and executes the recovered Toyota resolver stage appropriate to the VIN-source category. Phase5/Phase6 type-59 `CDbVinVehicleDecisionTable` hits are final at this stage. Phase3/Phase4 hits are explicitly non-final because Toyota next runs the Spe-master probe program and type-41 `CDbVehicleDecisionTable`; the CLI will not silently promote such a candidate to a selected vehicle until that live stage is materialized. VIN10 itself rejects generation-low5 5..19, but Toyota's master separately binds legacy `SelectCarType.dll`/`SelectCarTypeVin.dll`; those binaries are absent from the current GTS+ corpus, so that path is reported as unresolved rather than unsupported. `vehicle mounted` starts from the selected Toyota vehicle's own install sets and keeps every logical category. Class-`0x10D` supplies the category+phase route, and the bundle also records Toyota's selected transport controller rather than assuming every raw address field is an 11-bit CAN ID. Phase `0x12` categories use the Phase5 ISO15765 controller and ordinary/extended-address routes (for example Camry FRC `0x792`, Combination Meter `0x7C0`, or TPM `0x750/0x2A`). Phase `0x18`/`0x38` selects `CCommCtrlISO15765_29BitCan`; its class-`0x10D +0x08` byte is a target address and materializes as normal-fixed `0x18DA<target>F1` with response `0x18DAF1<target>` (for example P6 Engine category 6000 target `00` -> `0x18DA00F1`). Other Toyota controller families remain represented even when this Panda runtime does not implement them; that state is `probe_unavailable`, not category absence. Class-`0x10D +0x14` is interpreted as a standard legislated physical request only when it lies in `0x7E0..0x7E7`; other values are preserved as route metadata rather than rejected. Timeouts remain observations, not absence claims.

`did support CATEGORY [DID...]` dispatches through Toyota's selected support **mode**, not merely the shared plugin name. Ordinary Toyota P5 uses `22 01 01`, retains advertised `xx00` root IDs, expands MSB-first member bitmaps, and deliberately does not issue group queries for Toyota's `F300`/`FD00` exclusions. P5 partner/Hino modes remain separately classified rather than inheriting that algorithm. Standard P6 uses `22 A1 00`; its first bitmap advertises `A1nn` selector IDs, ordinary selectors are queried as `22 A1 nn`, and their bitmaps expand to `nn00..nnFF`; `A1FD`/`A1FE` remain advertised selectors but Toyota does not expand them. `rid support` reproduces the parallel P6 routine hierarchy: `31 01 D1 00` -> advertised `D1nn`, ordinary `31 01 D1 nn` selector queries -> `nn00..nnFF`, with `D1F0`/`D1FE` retained but not expanded. A known Toyota support mode for which the exact local executor has not been recovered is reported as executor-unavailable, never as an unsupported ECU.

The exact Camry maintenance clear is now:

```bash
./tools/toyota dtc clear
```

It scans the exact 17-address post-repin maintenance set, attempts physical `14 FF FF FF` on responding ECUs, sends the validated functional `0x7DF` Mode 04 frame, then rescans and fails if any `status & 0xAF` fault bits remain. Exact-F33 F181 remains available as an identity observation, but it is not re-read as an admission check before clearing.

Raw/functional requests use a small service classifier only to decide whether explicit `--force` acknowledgement is required. That acknowledgement is a CLI user-intent boundary, not a Toyota capability resolver or vehicle-permission layer; after it is supplied, an explicit numeric endpoint is not required to be pre-registered.

Active-Test execution keeps **complete request geometry** separate from incomplete plans. The legacy Camry v6 fixture contains 428 candidates: 41 rows whose fixed request geometry is complete, 361 plan-only rows, and 26 unresolved rows. `executor.py` rejects malformed/placeholder identifiers (for example a recovered `0xFFFF` RID) and requires every byte needed to construct the request. In the universal bundle, lifecycle comes directly from the selected Toyota category's exported D1/D2/DD metadata; support-family selection is not a second session permission gate, and there is no `wire_proven_categories`, supported-generation, or category allowlist in the executor. Fixed routine controls such as FRC `0xA429` LTA Steering Vibration remain runtime-executable where their geometry is complete, while direct `0x2F` tests remain plan-only when their exact runtime payload length is unrecovered. The registry also carries raw Toyota CommSet rows (for example CommSet 1 `receive_timeout=1020`, retry count 1); the runtime exposes those rows but deliberately does not reinterpret the raw timeout as seconds until Techstream's `CheckAndConvertRcvTimeOut` conversion is fully recovered.

Viewing and listing never transmits. `active-test list --json` and `active-test plan --json` expose the registry geometry grade and concrete runtime construction failures, so automation does not have to infer executability from the catalog. Mutation requires the literal `--execute` user acknowledgement; without `--execute`, `active-test run/stop` is a dry-run. There is no second F181 or session-acknowledgement gate. Started operations always attempt their recovered stop/return-control request on exception or Ctrl-C, and context cleanup returns an extended session to D1. Cleanup failures are surfaced separately and produce a nonzero result instead of looking successful.

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

Registry v3 adds the current Camry-HV GTS CAN Bus Check topology plus tracked EPS/FRC/Brake identity observations. `can topology` shows Toyota's vehicle-network domains (for example Front Camera Module on GTS Bus 1 and EPS/Skid Control on GTS Bus 4 behind Central Gateway); those labels are explicitly **not** Panda bus numbers. `ecu info` shows observed F181/F18C/part identities where available and labels their 2026-08-26 Panda-bus1 route as historical pre-repin evidence. Toyota's universal resolver does not assign a Panda bus: that is installation/harness-local state. The CLI currently defaults its local live transport binding to Panda bus 0 because that is the maintainer Camry's post-repin diagnostic route; `--bus` overrides it explicitly. Library-created universal profiles remain unbound until a caller supplies a bus.

`did read` and `did watch` accept multiple DID numbers or GTS names for one ECU and reuse a single UDS client. `--json` on `read` emits one machine-readable snapshot; `--json` on `watch` emits one JSON object per sample group, making the same phone/SSH command useful as a lightweight capture logger without a separate script. `can sniff` is strictly receive-only: with `pandad` running it subscribes to the public `can` service regardless of Panda safety mode, and with `pandad` stopped it reads directly from Panda without changing safety. It can filter multiple addresses and emit JSONL for analysis captures.

Use `--registry FILE` or `--profile PROFILE_NAME` to load another supported derived registry when additional vehicles are added. The loader accepts v1-v6 for backward compatibility. Engineering-value decoding requires explicit decoder metadata; topology/observed identities require the corresponding v3+ fields; execution/session behavior requires explicit v4 lifecycle and operation metadata; Toyota VIN/install-set metadata first appears in v5, while category-native live routing requires v6 `vehicle_resolution.mount.candidates[].transport_route`. Nothing is inferred for older registries.
