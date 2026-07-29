# TSK Camry field session

This branch tests whether the recovered Sienna EPS diagnostic and payload path
transfers to another Toyota TSS 3 calibration. An unknown fingerprint is evidence,
not a software gate: the UI identifies it first and still exposes the explicit
Sienna-transfer operations.

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

The launcher writes the web-server log to
`/cache/tsk/logs/tsk-web.log`. The offroad alert shows the reachable web URL.

## Field workflow

1. **EPS fingerprint and service map** — reads the identity block and records the
   observed diagnostic response ID/bus. The known `0x7A1 -> 0x7A9` route is tested
   first but the response ID is discovered rather than assumed.
2. **Passive CAN inventory** — observes arbitration IDs, buses, and frame widths.
3. **Not Ready to Drive UDS sweep** — exhaustive and resumable. Observation-oriented
   services run first. Stateful subfunctions run later with per-request restoration,
   liveness checks, TesterPresent, route rediscovery, and long-timeout rechecks.
4. **Passive READY capture** — appends every non-echo CAN payload and sends nothing.
5. **Active READY diff** — separately replays only bare service requests already
   characterized in the Not Ready to Drive transcript.
6. **Sienna transfer hypothesis** — explicitly tests the known programming,
   SecurityAccess, payload, callback, and DataFlash paths regardless of fingerprint.
7. **Evidence export** — download the bundle before clearing data or moving to the
   next active experiment.

The Sienna/Corolla sync IDs, protected IDs, diagnostic addresses, DataFlash layout,
and seed/key material remain labeled hypotheses. They annotate captures and seed
explicit transfer tests; they do not filter passive evidence.

## Durable evidence

Field transcripts are append-only under `/cache/tsk/` until an AGNOS update or
manual deletion. The bundle endpoint produces:

```text
/api/evidence-bundle
```

The `.tar.gz` contains `session-manifest.json`, operation history, raw NDJSON
captures, UDS transcripts, DataFlash binaries, payload hashes, job states, and device
logs. The manifest records the openpilot branch/commit and a hash prefix rather than
the plaintext dongle ID.

## Local tests

```bash
python3 -m unittest discover -s tsk/tests -v
python3 -m compileall -q tsk
bash -n launch_chffrplus.sh
```
