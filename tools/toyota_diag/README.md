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

Live commands have two transport modes. If `pandad` is stopped, the CLI takes direct Panda ownership using the exact live-validated Camry ELM327 setup. If `pandad` is already running, the CLI reuses openpilot's `can`/`sendcan` ISO-TP path **only** when the one live Panda is already in ELM327 safety param 1 with `controlsAllowed=false` on the profile's validated bus-0 topology. It never changes a running Panda's safety mode; if openpilot has already transitioned to Toyota/onroad safety, the command fails closed and tells you to stop manager for direct access. `./tools/toyota transport status` checks this gate without transmitting anything.

```bash
./tools/toyota transport status
./tools/toyota can sniff 0xB6 --duration 10
./tools/toyota can sniff 0x30 0x412 --duration 0 --json > can.jsonl
./tools/toyota dtc scan
./tools/toyota did read eps 0x1037
./tools/toyota did watch frc 0x1601 0x1501 0x1681 0x1903 --interval 0.25
./tools/toyota did watch frc 0x1601 0x1501 --json > frc-monitor.jsonl
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

`did read` and `did watch` accept multiple DID numbers or GTS names for one ECU and reuse a single UDS client. `--json` on `read` emits one machine-readable snapshot; `--json` on `watch` emits one JSON object per sample group, making the same phone/SSH command useful as a lightweight capture logger without a separate script. `can sniff` is strictly receive-only: with `pandad` running it subscribes to the public `can` service regardless of Panda safety mode, and with `pandad` stopped it reads directly from Panda without changing safety. It can filter multiple addresses and emit JSONL for analysis captures.

Use `--registry FILE` to load another supported derived registry when additional vehicles are added. The loader accepts v1 for catalog/backward compatibility, but engineering-value decoding requires explicit v2 decoder metadata; it is never inferred for older registries.
