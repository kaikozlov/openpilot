#!/usr/bin/env python3
"""Find and verify the Toyota SecOC key inside a DataFlash dump.

This is pure computation — it takes the 32KB dump (from dump_dataflash.py) plus a
CAN oracle (sync + protected frames captured from the bus) and returns the key or
nothing. It never touches the car, so it is not is_agnos-gated and runs anywhere
the two input files exist.

Design (per the 2026-07-05 decisions, refined by the 2026-08 cross-variant work):
  - Car-agnostic. No model gate. Cryptographic verification is the safety net.
  - No entropy filter, score cutoff, or candidate cap: every byte-aligned 16-byte
    DataFlash window is eligible, subject only to the coverage mask for a partial.
  - The first pass is the union of several sync samples and a small spread of
    protected samples from every observed classic CAN ID. A protected-message key
    therefore survives even if a different key authenticates the sync stream.
  - Acceptance uses absolute matches, not percentages: a candidate must authenticate
    at least MATCH_FLOOR samples and establish a real domain (>= MIN_SYNC_MATCHES
    sync matches or >= MIN_PROTECTED_MATCHES protected matches). A wrong window
    clears a 28-bit sync MAC with p=2^-28 and a protected sample's 64 counter trials
    with p~2^-22, making dozens of independent matches cryptographically decisive.
  - Generic cryptographic validity is separate from installation. The caller installs
    SecOCKey only when the candidate also verifies the current openpilot control IDs.

The AES-CMAC framing semantics (subkeys, first28/tail28, sync input, freshness, and
classic protected input) match the proven reference verifier/openpilot SecOC sender.
Protected counter trials are batched into one ECB call per sample for scan efficiency;
this is an implementation optimization, not a framing change.

This module does not install the key. It returns the key hex to the caller, which
installs via KeyFileManager (same split as /api/extract).
"""
import struct
import time
from pathlib import Path

from Crypto.Cipher import AES

from tsk.lib.dump_dataflash import (
  DUMP_START, DUMP_TOTAL, dump_path, partial_coverage_path, partial_dump_path,
)
from tsk.lib.env import CAN_ORACLE_PATH
from tsk.lib.secoc_discovery import load_oracle_discovery
from tsk.lib.secoc_profile import (
  CLASSIC_PROTECTED_ADDRS, CURRENT_OPENPILOT_LATERAL_PROTECTED_ADDRS,
  CURRENT_OPENPILOT_LONGITUDINAL_PROTECTED_ADDRS, SYNC_ADDR,
)

# Acceptance: a window must authenticate at least MATCH_FLOOR oracle samples
# (sync + protected), of which at least MIN_SYNC_MATCHES are sync. MATCH_FLOOR is
# far above the noise floor for a wrong key (~2^-660) and easily reached by a real
# capture (tens of sync + hundreds of protected), so a few corrupt frames don't
# reject the key. Raising MATCH_FLOOR buys no safety and only demands a richer
# capture, so it is kept modest.
MATCH_FLOOR = 30
MIN_SYNC_MATCHES = 2
MIN_PROTECTED_MATCHES = 2
MIN_CONTROL_MATCHES_PER_ID = 2
FIRST_PASS_SAMPLES = 5
FIRST_PASS_PROTECTED_PER_ID = 2

# Oracle framing matches the reference sender. Known Toyota IDs are hypotheses, not
# a parser filter: secoc_discovery can admit unknown classic streams when their
# trailer behavior is structurally consistent with the current same-bus sync state.
PROTECTED_ADDRS = CLASSIC_PROTECTED_ADDRS

def oracle_path() -> Path:
  return Path(CAN_ORACLE_PATH)


# --- AES-CMAC (RFC 4493) primitives, matching opendbc/car/secoc.py ---

def _left_shift_one(buf: bytes) -> bytes:
  out = bytearray(len(buf))
  carry = 0
  for i in range(len(buf) - 1, -1, -1):
    out[i] = ((buf[i] << 1) & 0xFF) | carry
    carry = 1 if (buf[i] & 0x80) else 0
  return bytes(out)


def _xor(a: bytes, b: bytes) -> bytes:
  return bytes(x ^ y for x, y in zip(a, b, strict=True))


def _cmac_subkeys(key: bytes):
  L = AES.new(key, AES.MODE_ECB).encrypt(b"\x00" * 16)
  K1 = bytearray(_left_shift_one(L))
  if L[0] & 0x80:
    K1[15] ^= 0x87
  K2 = bytearray(_left_shift_one(bytes(K1)))
  if K1[0] & 0x80:
    K2[15] ^= 0x87
  return bytes(K1), bytes(K2)


def _aes_cmac_with_cipher(cipher, msg: bytes, subkeys) -> bytes:
  K1, K2 = subkeys
  n = max(1, (len(msg) + 15) // 16)
  complete = len(msg) > 0 and len(msg) % 16 == 0
  if complete:
    last = _xor(msg[(n - 1) * 16:n * 16], K1)
  else:
    chunk = (msg[(n - 1) * 16:] + b"\x80").ljust(16, b"\x00")
    last = _xor(chunk, K2)
  X = b"\x00" * 16
  for i in range(n - 1):
    X = cipher.encrypt(_xor(X, msg[i * 16:(i + 1) * 16]))
  return cipher.encrypt(_xor(X, last))


def _aes_cmac(key: bytes, msg: bytes, subkeys=None) -> bytes:
  subkeys = subkeys or _cmac_subkeys(key)
  return _aes_cmac_with_cipher(AES.new(key, AES.MODE_ECB), msg, subkeys)


def _first28(mac: bytes) -> int:
  return ((mac[0] << 20) | (mac[1] << 12) | (mac[2] << 4) | (mac[3] >> 4)) & 0xFFFFFFF


def _tail28(data: bytes) -> int:
  return (((data[4] & 0x0F) << 24) | (data[5] << 16) | (data[6] << 8) | data[7]) & 0xFFFFFFF


def _sync_input(trip: int, reset: int) -> bytes:
  return struct.pack(">HH", 0x0F, trip) + bytes(
    [((reset << 4) >> 16) & 0xFF, ((reset << 4) >> 8) & 0xFF, (reset << 4) & 0xFF])


def _freshness(trip: int, reset: int, msg_cnt: int) -> bytes:
  return struct.pack(">HI", trip & 0xFFFF,
                     ((reset & 0xFFFFF) << 12) | ((msg_cnt & 0xFF) << 4) | ((reset & 3) << 2))


def load_oracle_analysis(path: Path) -> dict:
  """Return sync samples plus known/structurally discovered classic SecOC streams."""
  return load_oracle_discovery(Path(path))


def load_oracle_samples(path: Path):
  """Compatibility tuple wrapper around the generalized discovery parser."""
  analysis = load_oracle_analysis(path)
  return analysis["sync_samples"], analysis["protected_samples"], analysis["malformed"]


def _verify_sync(key: bytes, samples, subkeys) -> int:
  matches = 0
  cipher = AES.new(key, AES.MODE_ECB)
  for s in samples:
    if _first28(_aes_cmac_with_cipher(cipher, _sync_input(s["trip"], s["reset"]), subkeys)) == s["auth"]:
      matches += 1
  return matches


def _protected_sample_matches(cipher, sample, subkeys) -> bool:
  """Check one classic protected sample against all 64 possible message counters.

  The trailer exposes msg_cnt low2 through the flag nibble. Every remaining candidate
  produces a one-block (12-byte) CMAC input, so all 64 padded final blocks can be
  encrypted in one ECB call instead of crossing Python/C for every counter.
  """
  reset_low2 = sample["reset"] & 3
  if (sample["flag"] & 3) != reset_low2:
    return False
  msg_low2 = (sample["flag"] >> 2) & 3
  K2 = subkeys[1]
  blocks = bytearray()
  for msg_cnt in range(msg_low2, 256, 4):
    msg = (struct.pack(">H", sample["addr"]) + sample["payload4"] +
           _freshness(sample["trip"], sample["reset"], msg_cnt))
    padded = (msg + b"\x80").ljust(16, b"\x00")
    blocks.extend(_xor(padded, K2))
  encrypted = cipher.encrypt(bytes(blocks))
  return any(_first28(encrypted[i:i + 16]) == sample["auth"]
             for i in range(0, len(encrypted), 16))


def _verify_protected(key: bytes, samples, subkeys) -> int:
  return _verify_protected_breakdown(key, samples, subkeys)[0]


def _verify_protected_details(key: bytes, samples, subkeys):
  matches = 0
  by_id: dict[int, int] = {}
  by_bus: dict[int, int] = {}
  by_stream: dict[tuple[int, int], int] = {}
  cipher = AES.new(key, AES.MODE_ECB)
  for s in samples:
    if _protected_sample_matches(cipher, s, subkeys):
      matches += 1
      by_id[s["addr"]] = by_id.get(s["addr"], 0) + 1
      by_bus[s["bus"]] = by_bus.get(s["bus"], 0) + 1
      stream = (int(s["bus"]), int(s["addr"]))
      by_stream[stream] = by_stream.get(stream, 0) + 1
  return matches, by_id, by_bus, by_stream


def _verify_protected_breakdown(key: bytes, samples, subkeys):
  matches, by_id, by_bus, _ = _verify_protected_details(key, samples, subkeys)
  return matches, by_id, by_bus


def _domain_kind(sync_matches: int, protected_matches: int) -> str:
  if sync_matches >= MIN_SYNC_MATCHES and protected_matches >= MIN_PROTECTED_MATCHES:
    return "sync+protected"
  if protected_matches >= MIN_PROTECTED_MATCHES:
    return "protected-only"
  if sync_matches >= MIN_SYNC_MATCHES:
    return "sync-only"
  return "unverified"


def _select_protected_probes(samples) -> list[dict]:
  """Choose a small spread per observed protected ID for the exhaustive first pass."""
  grouped: dict[int, list[dict]] = {}
  for sample in samples:
    grouped.setdefault(sample["addr"], []).append(sample)
  probes: list[dict] = []
  for addr in sorted(grouped):
    rows = grouped[addr]
    count = min(FIRST_PASS_PROTECTED_PER_ID, len(rows))
    indices = sorted({i * (len(rows) - 1) // max(1, count - 1) for i in range(count)})
    probes.extend(rows[i] for i in indices)
  return probes


def _compatibility_fields(by_id: dict[int, int]) -> dict:
  """Report compatibility with the *current* Toyota openpilot sender surface.

  These fields are never target discovery. A new target can have a valid key and a
  different protected control surface; that is why generic cryptographic validity is
  kept separate from this compatibility report.
  """
  lateral_matches = {
    f"0x{addr:03x}": int(by_id.get(addr, 0))
    for addr in sorted(CURRENT_OPENPILOT_LATERAL_PROTECTED_ADDRS)
  }
  lateral_missing = [
    addr for addr in sorted(CURRENT_OPENPILOT_LATERAL_PROTECTED_ADDRS)
    if by_id.get(addr, 0) < MIN_CONTROL_MATCHES_PER_ID
  ]
  longitudinal_matches = {
    f"0x{addr:03x}": int(by_id.get(addr, 0))
    for addr in sorted(CURRENT_OPENPILOT_LONGITUDINAL_PROTECTED_ADDRS)
  }
  longitudinal_missing = [
    addr for addr in sorted(CURRENT_OPENPILOT_LONGITUDINAL_PROTECTED_ADDRS)
    if by_id.get(addr, 0) < MIN_CONTROL_MATCHES_PER_ID
  ]
  return {
    "legacy_lateral_ready": not lateral_missing,
    "legacy_lateral_matches_by_id": lateral_matches,
    "legacy_lateral_missing": [f"0x{addr:03x}" for addr in lateral_missing],
    "legacy_longitudinal_ready": not longitudinal_missing,
    "legacy_longitudinal_matches_by_id": longitudinal_matches,
    "legacy_longitudinal_missing": [f"0x{addr:03x}" for addr in longitudinal_missing],
    # Backward-compatible aliases. They now explicitly mean legacy/current
    # openpilot lateral compatibility, not generic target-profile readiness.
    "control_ready": not lateral_missing,
    "control_matches_by_id": lateral_matches,
    "control_missing": [f"0x{addr:03x}" for addr in lateral_missing],
  }


def _base_result() -> dict:
  return {
    "status": "",       # found | not_found | insufficient_oracle | no_dump
    "key": "",
    "offset": -1,
    "address": "",
    "sync": "",
    "protected": "",
    "protected_by_id": {},
    "protected_by_bus": {},
    "protected_by_stream": {},
    "domain": "unverified",
    "legacy_lateral_ready": False,
    "legacy_lateral_matches_by_id": {},
    "legacy_lateral_missing": [f"0x{addr:03x}" for addr in sorted(CURRENT_OPENPILOT_LATERAL_PROTECTED_ADDRS)],
    "legacy_longitudinal_ready": False,
    "legacy_longitudinal_matches_by_id": {},
    "legacy_longitudinal_missing": [f"0x{addr:03x}" for addr in sorted(CURRENT_OPENPILOT_LONGITUDINAL_PROTECTED_ADDRS)],
    "control_ready": False,
    "control_matches_by_id": {},
    "control_missing": [f"0x{addr:03x}" for addr in sorted(CURRENT_OPENPILOT_LATERAL_PROTECTED_ADDRS)],
    "alternate_verified": [],
    "matches": 0,
    "windows_scanned": 0,
    "windows_eligible": 0,
    "coverage_known": False,
    "survivors": 0,
    "elapsed": 0.0,
    "malformed": 0,
    "dump_partial": False,
    "message": "",
  }


def find_key(dump: bytes, sync_samples, protected_samples, progress_cb=None, coverage: bytes | None = None) -> dict:
  """Exhaustively scan dump for a window that authenticates the CAN oracle.

  Pure function: no file or car I/O. The first pass takes the union of sync-domain
  matches and a small spread of protected samples per observed CAN ID. That prevents
  a separate protected-message key from being discarded merely because it does not
  authenticate the synchronization stream. Survivors are then fully verified.
  """
  result = _base_result()
  t0 = time.monotonic()
  n_windows = max(0, len(dump) - 15)
  n_sync = len(sync_samples)
  n_prot = len(protected_samples)
  result["windows_scanned"] = n_windows
  if coverage is not None and len(coverage) != len(dump):
    raise ValueError(f"coverage mask is {len(coverage)} bytes, expected {len(dump)}")
  result["coverage_known"] = coverage is not None
  result["windows_eligible"] = (n_windows if coverage is None else
                                sum(1 for off in range(n_windows) if all(coverage[off:off + 16])))

  if n_sync == 0:
    result.update(status="not_found", elapsed=time.monotonic() - t0,
                  message="No sync samples in the CAN oracle.")
    return result

  # First pass: union over a spread of sync samples and protected samples from every
  # observed classic ID. A protected-only key is therefore discoverable even when a
  # different key authenticates 0x00F.
  probe_idx = sorted({i * n_sync // FIRST_PASS_SAMPLES for i in range(FIRST_PASS_SAMPLES)})
  sync_probes = [(_sync_input(sync_samples[j]["trip"], sync_samples[j]["reset"]), sync_samples[j]["auth"])
                 for j in probe_idx]
  protected_probes = _select_protected_probes(protected_samples)
  survivors = []
  for off in range(n_windows):
    if coverage is not None and not all(coverage[off:off + 16]):
      continue
    window = dump[off:off + 16]
    subkeys = _cmac_subkeys(window)
    cipher = AES.new(window, AES.MODE_ECB)
    matched = any(_first28(_aes_cmac_with_cipher(cipher, tin, subkeys)) == target
                  for tin, target in sync_probes)
    if not matched:
      matched = any(_protected_sample_matches(cipher, sample, subkeys) for sample in protected_probes)
    if matched:
      survivors.append(off)
    if progress_cb is not None and (off & 0xFFF) == 0:
      progress_cb(scanned=off, total=n_windows, survivors=len(survivors))
  result["survivors"] = len(survivors)

  # Full verification. If multiple real key domains are present, prefer a key that
  # verifies the current openpilot control streams over a higher-volume sync-only key.
  evaluated = []
  for off in survivors:
    window = dump[off:off + 16]
    subkeys = _cmac_subkeys(window)
    sync_matches = _verify_sync(window, sync_samples, subkeys)
    prot_matches, by_id, by_bus, by_stream = _verify_protected_details(window, protected_samples, subkeys)
    total = sync_matches + prot_matches
    compatibility = _compatibility_fields(by_id)
    evaluated.append({
      "offset": off,
      "key": window,
      "sync": sync_matches,
      "protected": prot_matches,
      "total": total,
      "by_id": by_id,
      "by_bus": by_bus,
      "by_stream": by_stream,
      "domain": _domain_kind(sync_matches, prot_matches),
      **compatibility,
      "verified": (total >= MATCH_FLOOR and
                   (sync_matches >= MIN_SYNC_MATCHES or prot_matches >= MIN_PROTECTED_MATCHES)),
    })

  result["elapsed"] = time.monotonic() - t0

  if not evaluated:
    result.update(status="not_found", sync=f"0/{n_sync}", protected=f"0/{n_prot}",
                  message=("No window authenticated the CAN oracle. The key is not in this " +
                           "dump, or the capture is bad — re-collect CAN and try again."))
    return result

  verified = [candidate for candidate in evaluated if candidate["verified"]]
  control_verified = [candidate for candidate in verified if candidate["control_ready"]]
  if control_verified:
    best = max(
      control_verified,
      key=lambda candidate: (
        sum(candidate["by_id"].get(addr, 0) for addr in CURRENT_OPENPILOT_LATERAL_PROTECTED_ADDRS),
        candidate["total"],
      ),
    )
  elif verified:
    best = max(verified, key=lambda candidate: candidate["total"])
  else:
    best = max(evaluated, key=lambda candidate: candidate["total"])

  result["sync"] = f"{best['sync']}/{n_sync}"
  result["protected"] = f"{best['protected']}/{n_prot}"
  result["protected_by_id"] = {f"0x{k:03x}": v for k, v in sorted(best["by_id"].items())}
  result["protected_by_bus"] = {str(k): v for k, v in sorted(best["by_bus"].items())}
  result["protected_by_stream"] = {
    f"{bus}:0x{addr:03x}": count for (bus, addr), count in sorted(best["by_stream"].items())
  }
  result["domain"] = best["domain"]
  result.update(**_compatibility_fields(best["by_id"]))
  result["matches"] = best["total"]
  result["offset"] = best["offset"]
  addr = DUMP_START + best["offset"]
  result["address"] = f"0x{addr:08x}"
  result["alternate_verified"] = [
    {
      "offset": candidate["offset"],
      "address": f"0x{DUMP_START + candidate['offset']:08x}",
      "domain": candidate["domain"],
      "matches": candidate["total"],
      "sync": candidate["sync"],
      "protected": candidate["protected"],
      "control_ready": candidate["control_ready"],
      "protected_by_id": {f"0x{k:03x}": v for k, v in sorted(candidate["by_id"].items())},
    }
    for candidate in verified if candidate is not best
  ]

  accepted = best["verified"]
  if accepted:
    message = (f"SecOC key candidate found and cryptographically verified at 0x{addr:08x} " +
               f"({best['total']} matches: sync {result['sync']}, protected {result['protected']}).")
    if result["legacy_lateral_ready"]:
      message += " It also matches the current openpilot Toyota lateral SecOC IDs."
    else:
      message += (" Current-openpilot lateral compatibility remains incomplete for " +
                  f"{', '.join(result['legacy_lateral_missing'])}; this does not invalidate a different target profile.")
    result.update(status="found", key=best["key"].hex(), address=f"0x{addr:08x}", message=message)
  else:
    if best["total"] < MATCH_FLOOR:
      reason = f"{best['total']} matches, need at least {MATCH_FLOOR}"
    else:
      reason = (f"no authenticated domain reached its floor (sync {best['sync']}/{MIN_SYNC_MATCHES}, " +
                f"protected {best['protected']}/{MIN_PROTECTED_MATCHES})")
    result.update(status="not_found",
                  message=(f"Best window at 0x{addr:08x} was not trusted ({reason}). " +
                           "Re-collect CAN and try again."))
  return result


def verify_candidate_key(key: bytes, sync_samples, protected_samples) -> dict:
  """Cryptographically validate one candidate key against an already-parsed oracle.

  Uses the same acceptance floor as the exhaustive DataFlash scan. This is the trust
  boundary for RAM-extracted candidates: structure/checksum plausibility alone never
  installs a key on an unknown calibration.
  """
  result = _base_result()
  if len(key) != 16:
    result.update(status="not_found", message="Candidate key is not 16 bytes.")
    return result

  n_sync = len(sync_samples)
  n_prot = len(protected_samples)
  total_samples = n_sync + n_prot
  if n_sync < MIN_SYNC_MATCHES or total_samples < MATCH_FLOOR:
    result.update(status="insufficient_oracle",
                  sync=f"0/{n_sync}", protected=f"0/{n_prot}",
                  message=(f"Not enough CAN data to verify the candidate (sync {n_sync}, " +
                           f"protected {n_prot}; need at least {MATCH_FLOOR} total and " +
                           f"{MIN_SYNC_MATCHES} sync)."))
    return result

  subkeys = _cmac_subkeys(key)
  sync_matches = _verify_sync(key, sync_samples, subkeys)
  protected_matches, by_id, by_bus, by_stream = _verify_protected_details(key, protected_samples, subkeys)
  matches = sync_matches + protected_matches
  result.update(
    sync=f"{sync_matches}/{n_sync}",
    protected=f"{protected_matches}/{n_prot}",
    protected_by_id={f"0x{k:03x}": v for k, v in sorted(by_id.items())},
    protected_by_bus={str(k): v for k, v in sorted(by_bus.items())},
    protected_by_stream={f"{bus}:0x{addr:03x}": count for (bus, addr), count in sorted(by_stream.items())},
    domain=_domain_kind(sync_matches, protected_matches),
    matches=matches,
    **_compatibility_fields(by_id),
  )
  if (matches >= MATCH_FLOOR and
      (sync_matches >= MIN_SYNC_MATCHES or protected_matches >= MIN_PROTECTED_MATCHES)):
    message = (f"Candidate key cryptographically verified ({matches} matches: " +
               f"sync {result['sync']}, protected {result['protected']}).")
    if result["legacy_lateral_ready"]:
      message += " It also matches the current openpilot Toyota lateral SecOC IDs."
    else:
      message += (" Current-openpilot lateral compatibility remains incomplete for " +
                  f"{', '.join(result['legacy_lateral_missing'])}; this does not invalidate a different target profile.")
    result.update(status="found", key=key.hex(), message=message)
  else:
    result.update(status="not_found",
                  message=(f"Candidate key failed cryptographic verification ({matches} matches: " +
                           f"sync {result['sync']}, protected {result['protected']})."))
  return result


def verify_candidate_from_oracle(key: bytes, path: Path | None = None) -> dict:
  """Load the persisted oracle and verify one 16-byte candidate key."""
  try:
    analysis = load_oracle_analysis(path or oracle_path())
  except OSError:
    result = _base_result()
    result.update(status="insufficient_oracle", message="No CAN oracle found. Collect CAN messages first.")
    return result
  result = verify_candidate_key(key, analysis["sync_samples"], analysis["protected_samples"])
  result["malformed"] = analysis["malformed"]
  result["profile_discovery"] = {
    "streams": analysis["streams"],
    "unknown_structural_candidates": analysis["unknown_structural_candidates"],
    "unknown_scan_streams": analysis["unknown_scan_streams"],
  }
  return result


def run(progress_cb=None) -> dict:
  """Load the dump and CAN oracle from disk and run find_key. Returns the result
  dict; does not install the key.

  Prefers the complete dump; if only a partial (.partial sidecar) exists, runs on
  that. New partials carry a byte-coverage mask, so only fully received 16-byte
  windows are scanned. Legacy partials without a mask retain the old zero-gap fallback;
  cryptographic verification still prevents an unverified window from being installed.
  """
  result = _base_result()

  complete_path = dump_path()
  partial_path = partial_dump_path()
  dump_is_partial = False
  coverage = None
  try:
    dump = complete_path.read_bytes()
  except OSError:
    try:
      dump = partial_path.read_bytes()
      dump_is_partial = True
      try:
        candidate_coverage = partial_coverage_path().read_bytes()
        if len(candidate_coverage) == DUMP_TOTAL:
          coverage = candidate_coverage
      except OSError:
        pass
    except OSError:
      result.update(status="no_dump", message="No DataFlash dump found. Dump DataFlash first.")
      return result
  if len(dump) != DUMP_TOTAL:
    result.update(status="no_dump",
                  message=f"Dump is {len(dump)} bytes, expected {DUMP_TOTAL}. Re-dump DataFlash.")
    return result

  try:
    analysis = load_oracle_analysis(oracle_path())
  except OSError:
    result.update(status="insufficient_oracle", message="No CAN oracle found. Collect CAN messages first.")
    return result

  sync_samples = analysis["sync_samples"]
  protected_samples = analysis["protected_samples"]
  malformed = analysis["malformed"]
  result["malformed"] = malformed
  result["profile_discovery"] = {
    "streams": analysis["streams"],
    "unknown_structural_candidates": analysis["unknown_structural_candidates"],
    "unknown_scan_streams": analysis["unknown_scan_streams"],
  }
  total = len(sync_samples) + len(protected_samples)
  if len(sync_samples) < MIN_SYNC_MATCHES or total < MATCH_FLOOR:
    msg = (f"Not enough CAN data (sync {len(sync_samples)}, protected {len(protected_samples)}; " +
           f"need at least {MATCH_FLOOR} total and {MIN_SYNC_MATCHES} observed sync samples " +
           "to reconstruct freshness). Collect more CAN.")
    if malformed:
      msg += f" ({malformed} malformed lines skipped.)"
    result.update(status="insufficient_oracle", message=msg)
    return result

  res = find_key(dump, sync_samples, protected_samples, progress_cb=progress_cb, coverage=coverage)
  res["malformed"] = malformed
  res["profile_discovery"] = result["profile_discovery"]
  res["dump_partial"] = dump_is_partial
  # A partial that fails to find the key most likely never captured the key's region.
  # The collapsed message is deliberate: the modal shows no debug block for a partial.
  if dump_is_partial and res["status"] == "not_found":
    res["message"] = "Key not found in the partial DataFlash dump."
  return res
