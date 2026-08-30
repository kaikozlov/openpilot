#!/usr/bin/env bash
# One-shot setup for exact-F33 development lateral on Kai's comma 4 / cuatro
# internal panda (HW_TYPE_CUATRO, unified panda_h7 firmware) — fork-only.
#
# Enables the zero-MAC28 B6 development path end-to-end:
#   params -> card.py dev-lateral arming -> TSS3_DEV_LATERAL panda safety -> B6 on bus 0.
#
# Preconditions (verified 2026-08-30):
#   - /data/openpilot is the non-release kai-openpilot fork with its exact nested
#     opendbc pin. The normal root SConstruct builds panda/board/obj/
#     panda_h7.bin.signed from that nested safety source; pandad flashes the
#     internal cuatro panda automatically when its signature differs.
#   - the EPS Gate-2 patch (build/out/secoc-patcher/f33) has been applied so
#     deliberately zero-MAC28 B6 frames pass the receiver check.
set -euo pipefail

P="/data/params/d"
FW="/data/openpilot/panda/board/obj/panda_h7.bin.signed"
CACHED_KEY="/cache/params/SecOCKey"

check_param() {
  local key="$1" expect="$2"
  local got
  got="$(cat "$P/$key" 2>/dev/null || true)"
  if [[ "$got" == "$expect" ]]; then
    echo "  [ok] $key = $expect"
  else
    echo "  [FAIL] $key: expected '$expect', got '$got'" >&2
    exit 1
  fi
}

echo "== fail-closed preflight =="
[[ -f "$FW" ]] || { echo "  [FAIL] normal openpilot build artifact missing: $FW" >&2; exit 1; }
check_param IsReleaseBranch 0
if [[ -s "$CACHED_KEY" ]]; then
  echo "  [FAIL] $CACHED_KEY is present and card.py will prefer it over the bridge" >&2
  exit 1
fi

echo
echo "== staging exact-F33 development lateral params =="
mkdir -p "$P"

# exact calibration binding, never a family selector
printf '8965F3307000' > "$P/ToyotaEphemeralSecOCBridgeF181"
printf '1' > "$P/ToyotaEphemeralSecOCBridge"
printf '1' > "$P/ToyotaTss3DevLateral"

# The cache-file override was rejected above. Remove only the ordinary Params
# copy so card.py cannot reuse stale key material from a previous launch.
rm -f "$P/SecOCKey"

sync

echo "== verifying =="
check_param ToyotaEphemeralSecOCBridgeF181 8965F3307000
check_param ToyotaEphemeralSecOCBridge 1
check_param ToyotaTss3DevLateral 1
[[ ! -e "$P/SecOCKey" ]] && echo "  [ok] SecOCKey absent" || { echo "  [FAIL] SecOCKey still present" >&2; exit 1; }
[[ ! -s "$CACHED_KEY" ]] && echo "  [ok] cached SecOCKey absent" || { echo "  [FAIL] cached SecOCKey appeared during setup" >&2; exit 1; }
check_param IsReleaseBranch 0

echo
echo "== next =="
echo "  1. reboot the device (or restart manager) so card.py re-reads params"
echo "  2. ignition ON, wait for EPS fw query; look for the arming line in logs:"
echo "     'Enabled exact-F33 TSS3 dev lateral (zero-MAC28 B6 via installed EPS bridge)'"
echo "  3. verify pandad reports the connected signature equals its expected signature"
echo "     and the panda version is DEV-...-DEBUG"
echo "  4. only then proceed to the stationary ladder (ID0 -> ID11-zero -> tiny step)"
