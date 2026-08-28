# Toyota diagnostics CLI

`tools/toyota` is the single Comma-side entry point for Toyota diagnostics recovered from Techstream/GTS+. The bundled `camry-2026-f33` registry is a generated, derived artifact: it contains ECU names/addresses, GTS DID/DTC catalogs, static Active-Test plans, the exact F33 identity guard, and the live-validated DTC-clear route. It does **not** contain Toyota DLL/DDB binaries.

Offline discovery works without Panda access:

```bash
./tools/toyota ecu list
./tools/toyota ecu info eps
./tools/toyota did list frc "LTA Control Condition"
./tools/toyota dtc catalog frc U0131
./tools/toyota active-test plan frc 0xA429
```

Live reads require `pandad` to be stopped so the process has exclusive Panda ownership:

```bash
./tools/toyota dtc scan
./tools/toyota did read eps 0xF181
./tools/toyota uds raw eps 0x22 F181
```

The exact Camry maintenance clear is now:

```bash
./tools/toyota dtc clear
```

It verifies EPS F181 contains `8965F3307000`, scans the exact 17-address post-repin set, attempts physical `14 FF FF FF` on responding ECUs, sends the validated functional `0x7DF` Mode 04 frame, then rescans and fails if any `status & 0xAF` fault bits remain.

Raw/functional requests that are not in the explicit read-only allowlist require `--force` **and** the same vehicle identity guard. Unknown/proprietary service IDs therefore fail closed rather than being assumed harmless.

Active Tests are intentionally **plan-only**. The registry exposes recovered `0x2F` direct and `0x31` routine wire plans, but this CLI has no Active-Test execution path. DID reads likewise print raw bytes plus GTS-derived signal metadata; value extraction/endian semantics are not guessed until the Techstream Data Monitor decode path is recovered completely.

Use `--registry FILE` to load another registry produced by the same `toyota-diagnostics-registry-v1` schema when additional vehicles are added.
