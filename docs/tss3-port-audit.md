# TSS3 port audit

First audit 2026-09-21; rewritten 2026-10-09 against the current tree (openpilot `cb31aedfe`, opendbc `9bdacdd74`, panda `92eb56516`). Static review, unit tests, and CI-path analysis only — no hardware, live CAN, or road validation, and nothing here certifies actuation safety.

## Verdict

The substantive port is sound and stays: vehicle decoding (`carstate.py`), radar track assembly (`radar_interface.py`), the TSS3 DBCs, independent safety enforcement (`safety/modes/toyota.h`), and standard controller integration. The original audit's worst findings are fixed: panda carries **zero** fork changes (the sample-point and BRS experiments were reverted; the pin is commaai master), the personality-synchronization policy is gone, the redundant radar path is consolidated, and topology is one definition — `ToyotaTSS3PlatformConfig`, toyota_b repin, chassis/state bus 0, FRC bus 2 — covering Camry and Crown. Corolla was deleted wholesale.

Two things are actually open:

1. **Crown has no validation route.** `TOYOTA_CROWN_TSS3` is registered (`values.py:251`) but has neither a route in `tests/routes.py` nor an exemption, so `test_models.py:169` raises `missing test route` and CI (`tests.yml:116`) fails. Beyond that, every TSS3 platform skips the controls tests (`test_models.py:293` — commands are built from live CAN and signer responses), so no TSS3 platform has recorded-route coverage of control generation; Camry's single route (`routes.py:240`) exercises decoding only. `docs/CARS.md` was regenerated for Camry but not Crown.
2. **Bringup automation ships inside the vehicle port.** ~1,650 changed lines across pandad lifecycle changes (`pandad.cc` +330/−13, `tss3_startup_catcher.h`), the oracle daemon and UI (`toyota_tss3_oracle_auto.py`, `tss3_oracle.py`), its tests, and manager registration. It arms on the TSS3 safety bit for any TSS3-flagged platform, and its signer tool lives at `/data/tss3-oracle/tss3-request-signer` (`toyota_tss3_oracle_auto.py:19`) — outside the git pins, so a checkout does not describe the working system. It is tested (19 passed) but is development tooling, not vehicle support.

Native startup pre-arm disables automatic CAN-FD promotion on all three Panda buses, matching normal TSS3 safety. This keeps explicitly Classical diagnostic packets Classical after FD wake traffic. The policy is preloaded while OFF, outside the ignition hot path.

Initial ELM327 firmware fingerprinting also disables automatic CAN-FD promotion on all three buses, matching Python Panda diagnostics. On the live Camry, automatic promotion allowed only ABS to answer; disabling it on the same bus 0 restored EPS, camera, and ABS Tester Present/F181 responses. Post-identification frame policy and strict firmware matching are unchanged.

Secondary: the fork is 32 commits (openpilot) and 11 commits (opendbc) behind commaai master — rebase hygiene, not a correctness issue. The opendbc lag touches no Toyota files; the parent lag intersects only `pandad/spi.cc`, which the bringup series modifies.

## In-repo signer boundary

`tss3.py` signs CONTROL_REQUEST (0x08A) through the **EPS-resident SecOC signer** over CAN — not the external oracle tool. Now 167 lines (down from 331) with a transport-shaped API — `receive` / `request_due` / `send` — and an in-file timing contract: 17–32 ms signer latency hidden by four pending requests, 90 ms response timeout, 100 ms CONTROL_REQUEST gap before the VMC latches a fault. The controller's only coupling is gating rate-limit advance on `request_due` (`carcontroller.py:103`), so driving intent stays in CarController and enforcement stays in safety. Do not merge this into `car/secoc.py`; the upstream helper is keyed authentication with different availability and lifecycle semantics.

Remaining gap: no deterministic offline double drives this boundary, which is why the model suite skips TSS3 controls tests.

## Ownership

| Owner | Responsibility |
| --- | --- |
| Upstream openpilot | Engagement, driver interaction policy, planning, longitudinal/lateral control, personality |
| opendbc Toyota interface/state/radar | Identify supported configuration; decode vehicle observations; expose standard CarParams, CarState, RadarData |
| opendbc Toyota controller | Translate standard CarControl into vehicle commands using existing limiting helpers |
| `tss3.py` SignerTransport | Represent the EPS signer exchange and its availability; no driving policy |
| opendbc safety | Independently restrict actuation and forwarding, with bounded failure behavior |
| panda | Unmodified upstream transport |
| Bringup (to be split out) | Prepare and inspect the development environment through a separately maintained lifecycle |

## Remaining work

1. Register a Crown route or exempt it deliberately — CI is red on `test_models` until then. Recover capture provenance: the deleted audit fixtures' `manifest.json` was the only record, and the Camry route's comment says only "openpilot longitudinal". Build a deterministic signer double and un-skip the TSS3 controls tests against it. Regenerate `CARS.md`.
2. Split bringup into its own review series: pandad startup/lifecycle, oracle daemon + UI, and external tool versioning. Until then it travels with every port change and vice versa.
3. Rebase both forks; only `pandad/spi.cc` conflicts with the bringup changes.

## Validation

Run 2026-10-09 with `opendbc_repo/.venv`:

- opendbc Toyota suites (`car/toyota/tests/`, `safety/tests/test_toyota.py`): **318 passed, 124 skipped, 272 subtests passed**. Skips are pre-existing platform/SecOC skips plus the TSS3 controls skip above.
- Parent TSS3 suites (`pandad/tests/test_direct_panda_lease.py`, `car/tests/test_toyota_tss3_oracle_*.py`): **19 passed, 22 subtests passed**.
- Previously recorded (2026-09): five recorded-route checks passed against the Camry capture; Toyota safety suites pass with their existing skips.
- Not run: full CI, MISRA coverage, hardware builds, live CAN, road tests.

## File inventory (merge-base diffs vs commaai master, 2026-10-09)

### opendbc — 22 files, +2,258 / −57

| File | +/- | Disposition |
| --- | --- | --- |
| `docs/CARS.md` | +2 / −1 | Regenerate; missing Crown. |
| `opendbc/can/dbc.py` | +4 / −1 | Keep; checksum dispatch for TSS3. |
| `opendbc/car/tests/routes.py` | +1 / −0 | Keep; add Crown route and provenance comments. |
| `opendbc/car/tests/test_fw_fingerprint.py` | +2 / −2 | Keep; query-time budget updates. |
| `opendbc/car/tests/test_models.py` | +2 / −0 | Replace blanket TSS3 skip with signer double. |
| `opendbc/car/torque_data/override.toml` | +2 / −0 | Keep. |
| `opendbc/car/toyota/carcontroller.py` | +59 / −1 | Keep; TSS3 update path. |
| `opendbc/car/toyota/carstate.py` | +168 / −2 | Keep; TSS3 decoding. |
| `opendbc/car/toyota/fingerprints.py` | +22 / −0 | Keep; captured identities. |
| `opendbc/car/toyota/interface.py` | +28 / −4 | Keep; TSS3 params wiring. |
| `opendbc/car/toyota/radar_interface.py` | +81 / −36 | Keep; consolidated TSS3 path. |
| `opendbc/car/toyota/tests/test_toyota.py` | +6 / −1 | Keep. |
| `opendbc/car/toyota/tests/test_tss3_camry.py` | +257 / −0 | Keep. |
| `opendbc/car/toyota/tests/test_tss3_radar.py` | +128 / −0 | Keep. |
| `opendbc/car/toyota/tests/test_tss3_transport.py` | +139 / −0 | Keep. |
| `opendbc/car/toyota/toyotacan.py` | +88 / −0 | Keep; message construction and checksums. |
| `opendbc/car/toyota/tss3.py` | +167 / −0 | Keep; SignerTransport. |
| `opendbc/car/toyota/values.py` | +62 / −3 | Keep; Camry + Crown definitions. |
| `opendbc/dbc/generator/toyota/toyota_tss3_pt.dbc` | +181 / −0 | Keep. |
| `opendbc/dbc/generator/toyota/toyota_tss3_radar.py` | +67 / −0 | Keep. |
| `opendbc/safety/modes/toyota.h` | +317 / −5 | Keep; independent TSS3 enforcement. |
| `opendbc/safety/tests/test_toyota.py` | +475 / −1 | Keep; merged TSS3 safety tests. |

### openpilot — 24 files, +1,926 / −65

| File | +/- | Disposition |
| --- | --- | --- |
| `.gitmodules` | +2 / −1 | Keep while fork pins are needed. |
| `opendbc_repo`, `panda` | pins | Keep. |
| `openpilot/common/params_keys.h` | +1 / −0 | Bringup series. |
| `openpilot/selfdrive/car/tests/test_toyota_tss3_oracle_kit.py` | +65 / −0 | Bringup series. |
| `openpilot/selfdrive/car/tests/test_toyota_tss3_oracle_reporting.py` | +171 / −0 | Bringup series. |
| `openpilot/selfdrive/car/toyota_tss3_oracle_auto.py` | +363 / −0 | Bringup series. |
| `openpilot/selfdrive/car/toyota_tss3_oracle_kit.py` | +30 / −0 | Bringup series. |
| `openpilot/selfdrive/car/toyota_tss3_oracle_status.py` | +58 / −0 | Bringup series. |
| `openpilot/selfdrive/pandad/main.cc` | +1 / −2 | Bringup series. |
| `openpilot/selfdrive/pandad/panda.cc` | +15 / −0 | Split: generic explicit-FD protocol vs bringup helper. |
| `openpilot/selfdrive/pandad/panda.h` | +2 / −1 | Split: protocol vs bringup. |
| `openpilot/selfdrive/pandad/panda_safety.cc` | +12 / −0 | Keep; scoped TSS3 safety param. |
| `openpilot/selfdrive/pandad/pandad.cc` | +330 / −13 | Bringup series. |
| `openpilot/selfdrive/pandad/pandad.h` | +3 / −1 | Bringup series. |
| `openpilot/selfdrive/pandad/pandad.py` | +143 / −27 | Bringup series. |
| `openpilot/selfdrive/pandad/tss3_startup_catcher.h` | +8 / −0 | Bringup series. |
| `openpilot/selfdrive/pandad/tests/test_direct_panda_lease.py` | +231 / −0 | Bringup series. |
| `openpilot/selfdrive/pandad/tests/test_pandad_canprotocol.cc` | +7 / −0 | Keep; protocol test. |
| `openpilot/selfdrive/ui/mici/layouts/main.py` | +3 / −1 | Bringup series. |
| `openpilot/selfdrive/ui/mici/layouts/settings/developer.py` | +38 / −2 | Bringup series. |
| `openpilot/selfdrive/ui/mici/layouts/settings/tss3_oracle.py` | +206 / −0 | Bringup series. |
| `openpilot/system/manager/process_config.py` | +4 / −0 | Bringup series. |
| `uv.lock` | +2 / −16 | Keep; consequence of pins. |

### panda — no fork changes

The pin equals commaai master `92eb56516`. Nothing to review or carry.
