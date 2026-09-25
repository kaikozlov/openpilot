# TSS3 port footprint and cleanup audit

Audit date: 2026-09-21. The inventory below records the initial architecture and source review before cleanup. It is not vehicle qualification or a diagnosis of a particular drive.

Follow-up implementation: the user selected repinned Camry as the single topology, requested deletion of other configurations (without new configuration-rejection logic), confirmed the panda timing/BRS changes were failed experiments, and requested removal of button-driven personality adjustment. Those changes are now in the working tree. Shared DBC evidence remains. Five standard recorded-route checks pass using the capture supplied from `sol`; 72 Toyota tests pass, and the Toyota safety suites pass with their existing skips. The authentication/controller scheduling boundary remains unresolved. Current scope and capture provenance are documented in `opendbc_repo/docs/TSS3.md`.

## Recommendation

Keep the vehicle decoding, radar work, normal controller integration, and independent safety checks. Split general panda changes from Toyota integration. Remove optional behavior that changes openpilot policy, and isolate development bringup. Preserve the requirement for an authentication capability, while treating its implementation as a separate dependency with an explicit contract.

The remaining problem is chiefly unclear ownership and incomplete integration validation. A wholesale rewrite would discard useful evidence and repeat the pattern that produced this history.

## Baseline and complete scope

Upstream master SHAs were verified through `gh api`; they match the available remote-tracking refs. Use the merge-base diff to identify work introduced by the fork, and a separate upstream-tip comparison to identify missing upstream changes. Mixing these comparisons incorrectly labels upstream improvements as port changes.

| Repository | Audited HEAD | Upstream master | Merge base | Fork diff |
| --- | --- | --- | --- | --- |
| openpilot | `63d92e313` | `521db4c825` | `3b2a75a4e` | 19 files, +1,279 / -67 |
| opendbc | `99a6ae862` | `4ad6045b2` | `b128914ad` | 24 files, +3,696 / -38 |
| panda | `c85577b0a` | `43ab39f7f` | `5314c84d9` | 10 files, +150 / -28 |

The parent file count includes two submodule pointers; do not count those as additional implementations. Binary fixture sizes are not included in line counts. Approximately 1,876 of opendbc's added lines are tests and fixture metadata, and another 423 are DBC definitions. Raw line count therefore overstates custom runtime machinery.

`msgq_repo`, `rednose_repo`, `teleoprtc_repo`, and `tinygrad_repo` have exactly the same pins as current upstream openpilot. All worktrees were initially clean. Generated DBCs and cached Python bytecode are not additional tracked port source.

Upstream lag is small but must be handled separately:

- opendbc is four upstream commits behind: Tesla changes and a lockfile update. These create ten additional file differences against upstream tip; they are not Toyota modifications.
- openpilot is one upstream commit behind, affecting `openpilot/selfdrive/locationd/models/pose_kf.py`.
- panda's one upstream-only commit is patch-equivalent to local `79345169` (`safety_tick()` API compatibility). Against upstream tip, panda actually has nine differing files, +149 / -27. This API adjustment can disappear from the port patch stack.

## What the history establishes

The opendbc branch contains 92 commits outside current upstream history, and the parent 79. Early work combined identity resolution, multiple harness arrangements, authentication, control ownership, and control tuning. Subsequent commits repeatedly changed takeover, override, freshness, recovery, and transport behavior. This supports a diagnosis of changing contracts across layers; it does not identify a single commit responsible for every reported driving bug.

Recent cleanup is real:

- opendbc `fc946e3f` removed the custom platform resolver and shared firmware-query plumbing.
- opendbc `b46f7528` restored shared safety contracts and removed further custom machinery.
- parent `0f58adbb5` removed the bespoke runtime scheduler.

At the audited HEAD, opendbc's `car.capnp`, `interfaces.py`, `car_helpers.py`, `fw_versions.py`, `fw_query_definitions.py`, `secoc.py`, `safety/lateral.h`, and `safety/declarations.h` match upstream. The parent has no remaining fork diff in the planners, controlsd, selfdrived, or process-replay implementation. Do not propose removing those historical changes again.

## Findings and decisions

### 1. General panda behavior has been changed to satisfy one vehicle

**High priority; confirmed source behavior, hardware consequences unmeasured.**

`panda/board/stm32h7/llfdcan_declarations.h:9` changes the shared data-phase sample point from 80% to 70%, with an F33-specific comment. `board/stm32h7/llfdcan.h:84` uses this constant for every data rate other than 5 Mbit/s. Its scope is therefore even broader than the constant's 2M name suggests.

`panda/board/drivers/fdcan.h:117` also makes host BRS depend on `canfd_auto`. Disabling automatic FD selection now forces host BRS off even when the configured data speed requests it. Previously these were separate decisions. This changes an existing API's meaning for other callers, not just TSS3.

**Decision:** these need standalone transport review. Preserve upstream defaults unless general evidence justifies changing them. If hardware needs an exception, express it through a deliberately scoped transport configuration rather than a global Toyota-derived default. Validate forwarding format, explicit host format, BRS, and both harness orientations independently. Do not blindly revert these changes on a working vehicle: their necessity has not been disproved.

The checksum validation and host-metadata sanitization in `board/can_comms.h` are defensible infrastructure work. Exact forwarded-frame preservation is also a defensible requirement. Their current use of `returned`/`rejected` bits as queue-private metadata needs clear ownership and regression coverage. The modified USB tests exercise parsing and queue behavior; their host `process_can()` is stubbed in `tests/libpanda/panda.c:6`, so they do not establish actual FDCAN register output or timing correctness.

The orientation change in `board/main_comms.h:261` follows the driver's existing physical-index access for FD mode. Other bus configuration fields use logical indexing. Treat that as a reason to test the whole configuration contract, not as evidence that simply changing this line back is correct.

### 2. Standard upstream car-model validation is missing for both new platforms

**High priority; confirmed integration gap.**

Neither `TOYOTA_CAMRY_TSS3` nor `TOYOTA_COROLLA_TSS3` has an entry in `opendbc/car/tests/routes.py`, and neither is in its explicit exemption list. A local inventory check confirmed zero routes for each. `test_models.py:166` raises an error when such a platform is selected. The upstream CI workflow calls this suite in `.github/workflows/tests.yml:116`.

The custom fixtures are useful, but their manifest explicitly says the working capture translates a historical repin for the test and is not stock-harness road qualification. The other capture has an absent EPS and is intended to fail liveness. These prove specific decoding and rejection behavior, not complete production readiness.

**Decision:** integrate representative, version-identified captures into the existing route test path. Preserve the custom fixtures for regression cases. Cover each supported hardware arrangement explicitly; do not add blanket exemptions simply to make CI green. Use the existing CarState/safety agreement and controller tests before inventing another replay framework. Offline authentication behavior can be represented by a deterministic test double at its boundary.

### 3. The gap-personality implementation adds policy disguised as button input

**Medium priority; behavior reproduced offline.**

`opendbc/car/toyota/interface.py:36` continuously compares the stock distance selector with personality feedback received through `CarControl.hudControl.leadDistanceBars`. It emits synthetic press/release events until they agree. The parent consumes those events and changes the persistent personality in `selfdrived.py:461`.

A stationary selector with matching feedback emits zero events. Changing only the reported UI personality produces a synthetic `gapAdjustCruise` press and release, although no physical button moved. This means the car adapter can undo a user selection in the openpilot UI. The added convergence state is evidence of a new preference synchronization feature, not just CAN decoding.

**Decision:** remove continuous absolute synchronization from the minimal port. Default to the existing user-visible personality behavior and supported physical button events. If exact four-position/three-personality synchronization is wanted, make it a separately specified feature with explicit precedence and startup behavior. Merely moving it from the parent into Toyota did not eliminate the added policy.

### 4. The authentication adapter still crosses several ownership boundaries

**Medium priority; architectural finding, not an identified exploit or a proposed authentication implementation.**

`opendbc/car/toyota/tss3.py` is 331 lines and holds command snapshots, transaction state, publication timing, arm/release state, and availability. `CarController` asks it whether a control generation is due (`carcontroller.py:110`), while `CarInterface.update()` feeds it raw CAN and maps its availability into car faults (`interface.py:56`).

Asynchronous authentication legitimately needs state and deadlines. Those lines are not all removable duplication. But calling this component “transport” does not make the boundaries clear: it influences when controller state advances and participates in ownership transitions.

**Decision:** retain a narrow Toyota-local authentication boundary. Document command input, freshness/readiness output, cancellation, and failure behavior, then test it with a deterministic offline stand-in. Keep driving intent and standard actuator limiting in CarController and keep independent enforcement in safety. Avoid another framework or another shared controller. An interface boundary is sufficient; a new daemon is not inherently necessary.

Do not merge this into `car/secoc.py` merely because both involve SecOC. The upstream helper performs keyed authentication; the current external capability has different availability and lifecycle semantics. This audit treats that capability as a dependency and does not redesign its ECU implementation or installation mechanism.

### 5. Topology scope was collapsed to one repinned TSS3 layout

**Resolved by support-scope decision.**

The earlier audit found three simultaneously maintained configurations: stock-wired Camry, repinned Camry, and Corolla. That parallel topology work has now been retired. All maintained TSS3 integration uses the Toyota-B repin directly: chassis/state bus 0, FRC/source bus 2, and the unsplit auxiliary/radar bus 1. Raw stock-harness captures remain evidence/provenance only and are never used to select a runtime bus layout.

Python now derives these roles from one TSS3 topology definition rather than treating model-specific bus placement as a capability. Corolla registration and its separate control/safety path remain removed; the retained Corolla tests exercise shared wire formats on the canonical repinned bus placement. C safety still independently enforces the corresponding bus contract, as it should.

The current supported Camry uses openpilot longitudinal control on that one topology. Vehicle identity and authentication readiness remain distinct: `secOcRequired=False` means no host key is required, not that authentication is unnecessary.

### 6. Radar contains real protocol work plus one redundant path

**Low priority cleanup; preserve the substantive implementation.**

The TSS3 radar path assembles synchronized geometry and motion, preserves lifecycle transitions across batched CAN, and retires tracks after gaps. These are legitimate vehicle integration responsibilities, not a replacement planner or tracking stack.

However, `RadarInterface.update()` dispatches TSS3 directly to `_update_tss3()` at line 65. The separate TSS3 branch inside `_update()` at line 155 is unreachable through that normal entry point and repeats part of the assembly policy.

**Decision:** consolidate on the public update path and remove the redundant branch after checking direct callers. Preserve lifecycle and corrupt/missing-frame tests. Do not replace the synchronization logic with a last-message-only parser to reduce line count.

### 7. Bringup is a substantial, separately scoped development feature

**Separate workstream, as requested.**

The parent adds an orchestration process, UI, native pandad startup logic, and cooperative device ownership. It also expects an external executable under `/data/tss3-oracle/`; that executable is outside the audited Git pins. A checkout of these repositories therefore does not describe every dependency of the working system. The Camry startup path now reads the kit's `bundle/unified.json` before arming and requires the exact `camry-8965F3307000` target, so a Corolla/Crown kit copied into the generic `/data/tss3-oracle/` location is rejected before it can touch Panda or the vehicle.

The automatic startup path is not purely a UI convenience in its current form: it changes pandad lifecycle and relies on a prepared external capability. Removing it without preserving an equivalent prepared environment changes what can run.

**Decision:** keep development convenience out of the definition of the vehicle port. Document the required external capability and version identity separately from vehicle support. Review the pandad lifecycle feature separately before shipping it. Preserve ordinary CAN I/O and safety initialization behavior, and avoid promoting vehicle-specific startup logic into shared process policy. A useful long-term bringup feature should have its own specification and validation.

## Intended ownership

| Owner | Responsibility |
| --- | --- |
| Upstream openpilot | Engagement, driver interaction policy, planning, longitudinal/lateral control, personality |
| opendbc Toyota interface/state/radar | Identify supported configuration; decode vehicle observations; expose standard CarParams, CarState and RadarData |
| opendbc Toyota controller | Translate standard CarControl into vehicle commands using existing limiting helpers |
| Toyota-local authentication boundary | Represent the required external authentication capability and its availability without inventing driving policy |
| opendbc safety | Independently restrict actuation and forwarding, with bounded failure behavior |
| panda | General CAN transport and device behavior, with explicit configuration where needed |
| Development bringup | Prepare and inspect the development environment through a separately maintained lifecycle |

Keep the existing standard paths wherever possible. A vehicle-specific protocol adapter, a DBC, and a safety mode extension are normal port work. A second engagement policy, preference controller, global vehicle-specific driver default, or parallel replay framework needs separate justification.

## Proposed cleanup sequence

1. **Freeze a reviewable baseline.** Record these three SHAs plus external dependency version and hardware configuration. Preserve the current working branch. Separate upstream lag from fork changes before rebasing anything.
2. **Close the validation gap.** Register real captures for the supported configurations in the standard model suite. Preserve existing fixtures and add only missing boundary cases. Establish the expected engagement, disable, override, fault, and availability behavior before behavioral refactoring.
3. **Make a small semantic cleanup.** Remove the continuous gap-personality override, consolidate the redundant radar path, and correct misleading comments such as torque metadata being “unused” (the base interface reads `MAX_LAT_ACCEL_MEASURED`). Keep substantive decoding and independent safety tests.
4. **Split panda transport work into independently reviewable changes.** Separate forwarding preservation, metadata validation, orientation behavior, passive connections, BRS semantics, and sample-point policy. Require actual transport/hardware evidence for timing and format changes. Absorb the already-upstream safety-tick adjustment.
5. **Clarify opendbc boundaries.** Centralize ordinary topology mapping and specify the authentication boundary using offline doubles. Make one boundary change at a time; preserve standard controller and safety ownership. Do not replace existing common helpers with newly generalized ones.
6. **Rebase the resulting vehicle port and qualify each supported configuration.** Run normal opendbc checks, complete safety checks, and the standard route suite. Then perform controlled hardware validation for transport, startup, and fault behavior. Keep automatic bringup in a separate review series.

A sensible end state is three review series: general panda infrastructure, opendbc Toyota integration, and optional parent development bringup. Parent protocol compatibility changes can accompany the transport series. The acceptance criterion is clear ownership and passing existing integration paths, not an arbitrary target line count.

## Validation performed and limits

- Compared net fork changes and upstream-tip drift in all three changed repositories; checked unchanged submodule pins and clean starting worktrees.
- Reviewed the changed architectural paths, upstream base-interface/event behavior, local tests, and fixture provenance.
- Ran `test_toyota`, `test_tss3_radar`, and `test_tss3_camry_audit`: **39 tests passed**. Corrupt/missing-CAN warnings were expected negative cases.
- Confirmed route registration is missing for both TSS3 platforms and reproduced the gap-policy feedback behavior without CAN I/O.
- Did not run full CI, full safety coverage/MISRA, a hardware build, live CAN, external authentication tooling, or road tests. No conclusion here certifies actuation safety or identifies the cause of a specific observed drive failure.

The initial `uv run --no-sync` encountered an incompatible local opendbc environment, recreated its ignored `.venv`, and then failed on missing dependencies. Successful checks used an isolated `uv run --no-project --python 3.12` environment with NumPy, pycapnp, pycryptodome, tqdm, and zstandard. No tracked dependency files were changed.

## File-by-file inventory

The following inventory records every merge-base-relative changed file, with recommended disposition. Paths are relative to the named repository. Line counts are additions/deletions, not total file size.

### opendbc

| File | +/- | Disposition |
| --- | --- | --- |
| `docs/CARS.md` | +4 / -1 | Regenerate from truthful, configuration-specific support definitions. |
| `opendbc/can/dbc.py` | +3 / -1 | Keep normal checksum dispatch integration. |
| `opendbc/car/tests/test_fw_fingerprint.py` | +2 / -2 | Keep relevant regression coverage; pair with standard integration and hardware coverage. |
| `opendbc/car/torque_data/substitute.toml` | +2 / -0 | Keep required metadata; correct unused-metadata comments and qualify substitutes. |
| `opendbc/car/toyota/carcontroller.py` | +103 / -3 | Keep standard control translation; clarify asynchronous boundary. |
| `opendbc/car/toyota/carstate.py` | +212 / -2 | Keep decoding; centralize topology; qualify platform-specific state semantics. |
| `opendbc/car/toyota/fingerprints.py` | +22 / -0 | Keep captured identities; distinguish identity from readiness. |
| `opendbc/car/toyota/interface.py` | +140 / -1 | Refactor topology; remove continuous preference synchronization; preserve standard capability contract. |
| `opendbc/car/toyota/radar_interface.py` | +118 / -17 | Keep lifecycle assembly; remove redundant private update branch. |
| `opendbc/car/toyota/tests/fixtures/camry_20260915_audit/manifest.json` | +102 / -0 | Keep evidence and provenance; do not treat translated fixtures as configuration qualification. |
| `opendbc/car/toyota/tests/fixtures/camry_20260915_audit/stock_harness_eps_absent.jsonl.gz` | binary | Keep evidence and provenance; do not treat translated fixtures as configuration qualification. |
| `opendbc/car/toyota/tests/fixtures/camry_20260915_audit/working_eps_repin.jsonl.gz` | binary | Keep evidence and provenance; do not treat translated fixtures as configuration qualification. |
| `opendbc/car/toyota/tests/test_toyota.py` | +12 / -2 | Keep relevant regression coverage; pair with standard integration and hardware coverage. |
| `opendbc/car/toyota/tests/test_tss3_camry.py` | +578 / -0 | Keep relevant regression coverage; pair with standard integration and hardware coverage. |
| `opendbc/car/toyota/tests/test_tss3_camry_audit.py` | +172 / -0 | Keep relevant regression coverage; pair with standard integration and hardware coverage. |
| `opendbc/car/toyota/tests/test_tss3_corolla.py` | +314 / -0 | Keep relevant regression coverage; pair with standard integration and hardware coverage. |
| `opendbc/car/toyota/tests/test_tss3_radar.py` | +182 / -0 | Keep relevant regression coverage; pair with standard integration and hardware coverage. |
| `opendbc/car/toyota/tests/test_tss3_transport.py` | +207 / -0 | Keep relevant regression coverage; pair with standard integration and hardware coverage. |
| `opendbc/car/toyota/toyotacan.py` | +62 / -0 | Keep message construction and checksum adaptation. |
| `opendbc/car/toyota/tss3.py` | +331 / -0 | Isolate/document external authentication boundary; no second driving policy. |
| `opendbc/car/toyota/values.py` | +92 / -7 | Keep platform definitions; document supported configuration matrix. |
| `opendbc/dbc/generator/toyota/toyota_tss3_pt.dbc` | +423 / -0 | Keep source DBC and evidence comments; generated copies are build artifacts. |
| `opendbc/safety/modes/toyota.h` | +308 / -2 | Keep independent enforcement; review alongside each supported configuration. |
| `opendbc/safety/tests/test_toyota_tss3.py` | +307 / -0 | Keep relevant regression coverage; pair with standard integration and hardware coverage. |

### panda

| File | +/- | Disposition |
| --- | --- | --- |
| `board/can_comms.h` | +18 / -3 | Separate general host-packet validation/sanitization change. |
| `board/drivers/can_common.h` | +5 / -0 | Separate forwarding-metadata contract. |
| `board/drivers/fdcan.h` | +13 / -7 | Separate forwarding preservation from changed host BRS policy; validate actual driver behavior. |
| `board/main.c` | +1 / -1 | Drop from port series when aligned with upstream: patch-equivalent API update. |
| `board/main_comms.h` | +8 / -2 | Separate configuration/orientation correction; validate both orientations. |
| `board/stm32h7/llfdcan_declarations.h` | +1 / -1 | Replace global vehicle-specific assumption with an evidence-based scoped policy. |
| `python/__init__.py` | +16 / -13 | Separate optional passive-connection API; document lifecycle semantics. |
| `tests/libpanda/libpanda_py.py` | +2 / -0 | Keep relevant regression coverage; pair with standard integration and hardware coverage. |
| `tests/libpanda/panda.c` | +4 / -0 | Keep relevant regression coverage; pair with standard integration and hardware coverage. |
| `tests/usbprotocol/test_comms.py` | +82 / -1 | Keep relevant regression coverage; pair with standard integration and hardware coverage. |

### openpilot

| File | +/- | Disposition |
| --- | --- | --- |
| `.gitmodules` | +4 / -2 | Keep fork routing while needed; branch hints are not a replacement for pinned gitlinks. |
| `opendbc_repo` | +1 / -1 | Keep deliberate, validated dependency pin. |
| `openpilot/common/params_keys.h` | +1 / -0 | Separate development bringup/lifecycle feature from the vehicle port. |
| `openpilot/selfdrive/car/toyota_tss3_oracle_auto.py` | +362 / -0 | Separate development bringup/lifecycle feature from the vehicle port. |
| `openpilot/selfdrive/pandad/main.cc` | +1 / -2 | Separate development bringup/lifecycle feature from the vehicle port. |
| `openpilot/selfdrive/pandad/panda.cc` | +15 / -0 | Separate generic explicit-FD protocol integration from bringup helper. |
| `openpilot/selfdrive/pandad/panda.h` | +2 / -1 | Protocol compatibility plus bringup helper declaration. |
| `openpilot/selfdrive/pandad/panda_safety.cc` | +18 / -0 | Reduce Toyota-policy duplication; preserve scoped transport configuration. |
| `openpilot/selfdrive/pandad/pandad.cc` | +261 / -13 | Separate development bringup/lifecycle feature from the vehicle port. |
| `openpilot/selfdrive/pandad/pandad.h` | +3 / -1 | Separate development bringup/lifecycle feature from the vehicle port. |
| `openpilot/selfdrive/pandad/pandad.py` | +143 / -27 | Separate development bringup/lifecycle feature from the vehicle port. |
| `openpilot/selfdrive/pandad/tests/test_direct_panda_lease.py` | +231 / -0 | Keep relevant regression coverage; pair with standard integration and hardware coverage. |
| `openpilot/selfdrive/pandad/tests/test_pandad_canprotocol.cc` | +1 / -0 | Keep relevant regression coverage; pair with standard integration and hardware coverage. |
| `openpilot/selfdrive/ui/mici/layouts/main.py` | +3 / -1 | Separate development bringup/lifecycle feature from the vehicle port. |
| `openpilot/selfdrive/ui/mici/layouts/settings/developer.py` | +33 / -2 | Separate development bringup/lifecycle feature from the vehicle port. |
| `openpilot/selfdrive/ui/mici/layouts/settings/tss3_oracle.py` | +193 / -0 | Separate development bringup/lifecycle feature from the vehicle port. |
| `openpilot/system/manager/process_config.py` | +4 / -0 | Separate development bringup/lifecycle feature from the vehicle port. |
| `panda` | +1 / -1 | Keep deliberate, validated dependency pin. |
| `uv.lock` | +2 / -16 | Keep only dependency-resolution consequences of chosen pins. |
