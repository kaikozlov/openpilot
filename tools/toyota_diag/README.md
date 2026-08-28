# Toyota diagnostics CLI

`tools/toyota` is the single Comma-side entry point for Toyota diagnostics recovered from Techstream/GTS+. The bundled `camry-2026-f33` registry is a generated, derived artifact: it contains ECU names/addresses, GTS DID/DTC catalogs, static Active-Test plans, the exact F33 identity guard, and the live-validated DTC-clear route. It does **not** contain Toyota DLL/DDB binaries.

Offline discovery works without Panda access:

```bash
./tools/toyota ecu list
./tools/toyota ecu info eps
./tools/toyota did list frc "LTA Control Condition"
./tools/toyota did decode eps 0x1037 0001
./tools/toyota dtc catalog frc U0131
./tools/toyota active-test plan frc 0xA429
```

Live reads require `pandad` to be stopped so the process has exclusive Panda ownership:

```bash
./tools/toyota dtc scan
./tools/toyota did read eps 0x1037
./tools/toyota did watch frc 0x1601 --interval 0.25
./tools/toyota uds raw eps 0x22 F181
```

The exact Camry maintenance clear is now:

```bash
./tools/toyota dtc clear
```

It verifies EPS F181 contains `8965F3307000`, scans the exact 17-address post-repin set, attempts physical `14 FF FF FF` on responding ECUs, sends the validated functional `0x7DF` Mode 04 frame, then rescans and fails if any `status & 0xAF` fault bits remain.

Raw/functional requests that are not in the explicit read-only allowlist require `--force` **and** the same vehicle identity guard. Unknown/proprietary service IDs therefore fail closed rather than being assumed harmless.

Active Tests are intentionally **plan-only**. The registry exposes recovered `0x2F` direct and `0x31` routine wire plans, but this CLI has no Active-Test execution path.

Registry v2 also carries the recovered ordinary-P5 Techstream Data Monitor decoder. `did read` always prints the raw DID value bytes first, then decodes each known signal using the registry-selected `p5-linear-msb0-v1` contract: MSB-first bit numbering, big-endian field assembly, two's-complement signed values, `trunc_toward_zero(raw * Mul / Div) + Offset`, exact decimal precision, and converted-value pattern labels. For example, EPS DID `0x1037` renders raw `0001` as `Steering Angle: 1.5 deg`; FRC DID `0x1601` renders Toyota's LTA/Hands-Off state labels. Unknown decoder kinds or undersized payloads fail closed and leave the raw bytes plus metadata visible.

Use `--registry FILE` to load another supported derived registry when additional vehicles are added. The loader accepts v1 for catalog/backward compatibility, but engineering-value decoding requires explicit v2 decoder metadata; it is never inferred for older registries.
