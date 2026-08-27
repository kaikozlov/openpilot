#!/usr/bin/env python3
"""Audit that a reviewed TSK target profile is actually implemented in opendbc.

This is the final static/software gate before stationary target verification. It is
intentionally conservative: a reviewed manifest cannot unlock SecOCKey installation
unless the checked-out opendbc Toyota sources contain the exact platform/F181 and agree
with the reviewed DBC, control mode, EPS scale, longitudinal ownership and safety param.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OPENDBC_ROOT = REPO_ROOT / "opendbc_repo"

ALLOWED_LONGITUDINAL_CONTROL = frozenset({"openpilot_default", "stock_default", "openpilot_alpha"})


def _sha256(path: Path) -> str:
  digest = hashlib.sha256()
  with path.open("rb") as fh:
    for block in iter(lambda: fh.read(1024 * 1024), b""):
      digest.update(block)
  return digest.hexdigest()


def _platform_block(values_source: str, platform_name: str) -> tuple[str, str] | None:
  # Toyota CAR entries are class-body assignments with two-space indentation. Stop at
  # the next platform assignment rather than attempting to execute the opendbc package.
  pattern = re.compile(
    rf"(?ms)^  {re.escape(platform_name)}\s*=\s*(?P<config>[A-Za-z_][A-Za-z0-9_]*)\((?P<body>.*?)" +
    r"(?=^  [A-Z][A-Z0-9_]+\s*=\s*[A-Za-z_][A-Za-z0-9_]*\(|\Z)"
  )
  match = pattern.search(values_source)
  if match is None:
    return None
  return match.group("config"), match.group("body")


def _fingerprint_block(fingerprint_source: str, platform_name: str) -> str | None:
  pattern = re.compile(
    rf"(?ms)^  CAR\.{re.escape(platform_name)}\s*:\s*\{{(?P<body>.*?)" +
    r"(?=^  CAR\.[A-Z][A-Z0-9_]+\s*:\s*\{|\Z)"
  )
  match = pattern.search(fingerprint_source)
  return None if match is None else match.group("body")


def _tss3_exact_fw_block(values_source: str, platform_name: str) -> str | None:
  pattern = re.compile(
    rf"(?ms)^TSS3_EXACT_FW_VERSIONS\s*=\s*\{{.*?^  CAR\.{re.escape(platform_name)}\s*:\s*\{{(?P<body>.*?)" +
    r"(?=^  CAR\.[A-Z][A-Z0-9_]+\s*:\s*\{|^\}|\Z)"
  )
  match = pattern.search(values_source)
  return None if match is None else match.group("body")


def _default_tss3_dbc(values_source: str) -> str | None:
  match = re.search(
    r"(?ms)^class ToyotaTSS3PlatformConfig\(PlatformConfig\):.*?" +
    r"dbc_dict\s*:\s*dict\s*=.*?Bus\.pt\s*:\s*['\"]([^'\"]+)['\"]",
    values_source,
  )
  return None if match is None else match.group(1)


def _default_secoc_dbc(values_source: str) -> str | None:
  match = re.search(
    r"(?ms)^class ToyotaSecOCPlatformConfig\(PlatformConfig\):.*?" +
    r"dbc_dict\s*:\s*dict\s*=.*?dbc_dict\(['\"]([^'\"]+)['\"]",
    values_source,
  )
  return None if match is None else match.group(1)


def _explicit_dbc(block: str) -> str | None:
  # PlatformConfig entries can pass either dbc_dict('name', ...) or a literal map.
  match = re.search(r"dbc_dict\(['\"]([^'\"]+)['\"]", block)
  if match:
    return match.group(1)
  match = re.search(r"Bus\.pt\s*:\s*['\"]([^'\"]+)['\"]", block)
  return None if match is None else match.group(1)


def _eps_scale(values_source: str, platform_name: str) -> int | None:
  match = re.search(
    r"(?ms)^EPS_SCALE\s*=\s*defaultdict\(lambda:\s*(\d+)\s*,\s*\{(?P<body>.*?)\}\s*\)",
    values_source,
  )
  if match is None:
    return None
  default = int(match.group(1))
  override = re.search(rf"CAR\.{re.escape(platform_name)}\s*:\s*(\d+)", match.group("body"))
  return int(override.group(1)) if override else default


def _safety_flag_values(values_source: str) -> dict[str, int]:
  match = re.search(
    r"(?ms)^class ToyotaSafetyFlags\(IntFlag\):(?P<body>.*?)(?=^class\s+ToyotaFlags\(IntFlag\):)",
    values_source,
  )
  if match is None:
    return {}
  out: dict[str, int] = {}
  for name, left, shift in re.findall(r"^\s+([A-Z_]+)\s*=\s*\((\d+)\s*<<\s*(\d+)\)", match.group("body"), re.M):
    out[name] = int(left) << int(shift)
  return out


def _parse_int(value) -> int | None:
  if isinstance(value, int):
    return value
  if isinstance(value, str):
    try:
      return int(value.strip(), 0)
    except ValueError:
      return None
  return None


def _dbc_generator_source(root: Path, dbc_name: str) -> Path | None:
  if not dbc_name.endswith("_generated"):
    return None
  base = dbc_name.removesuffix("_generated") + ".dbc"
  candidates = [
    root / "opendbc" / "dbc" / "generator" / "toyota" / base,
    root / "opendbc" / "dbc" / "generator" / base,
  ]
  return next((path for path in candidates if path.is_file()), None)


def audit_opendbc_implementation(identity: dict, integration: dict,
                                 *, opendbc_root: Path | None = None) -> dict:
  root = Path(opendbc_root or DEFAULT_OPENDBC_ROOT)
  checks: list[dict] = []

  def check(name: str, passed: bool, detail: str) -> None:
    checks.append({"name": name, "passed": bool(passed), "detail": detail})

  fields = integration.get("fields", {}) if isinstance(integration.get("fields"), dict) else {}
  if not integration.get("ready"):
    return {
      "ready": False,
      "root": str(root),
      "source_sha256": {},
      "checks": [{"name": "reviewed_integration_manifest", "passed": False,
                  "detail": "target integration manifest is not profile-bound, complete, evidenced and reviewed"}],
    }

  values_path = root / "opendbc" / "car" / "toyota" / "values.py"
  fingerprints_path = root / "opendbc" / "car" / "toyota" / "fingerprints.py"
  interface_path = root / "opendbc" / "car" / "toyota" / "interface.py"
  controller_path = root / "opendbc" / "car" / "toyota" / "carcontroller.py"
  required = (values_path, fingerprints_path, interface_path, controller_path)
  missing = [str(path) for path in required if not path.is_file()]
  check("opendbc_checkout_present", not missing,
        "Toyota source checkout present" if not missing else "missing: " + ", ".join(missing))
  if missing:
    return {"ready": False, "root": str(root), "source_sha256": {}, "checks": checks}

  values_source = values_path.read_text(encoding="utf-8")
  fingerprints_source = fingerprints_path.read_text(encoding="utf-8")
  interface_source = interface_path.read_text(encoding="utf-8")
  controller_source = controller_path.read_text(encoding="utf-8")

  platform_name = str(fields.get("platform_name", "")).strip()
  app_sw_id = str(identity.get("app_sw_id", "")).strip()
  requested_dbc = str(fields.get("dbc_pt", "")).strip()
  steer_control_type = str(fields.get("steer_control_type", "")).strip().lower()
  longitudinal_control = str(fields.get("longitudinal_control", "")).strip().lower()
  requested_eps_scale = _parse_int(fields.get("eps_scale"))
  requested_safety = _parse_int(fields.get("safety_flags"))

  valid_platform_name = bool(re.fullmatch(r"[A-Z][A-Z0-9_]+", platform_name))
  check("platform_name_shape", valid_platform_name, platform_name or "empty platform name")
  block_info = _platform_block(values_source, platform_name) if valid_platform_name else None
  check("platform_implemented", block_info is not None,
        f"CAR.{platform_name} exists in Toyota values.py" if block_info else f"CAR.{platform_name} is absent")

  config_class, block = block_info if block_info else ("", "")
  tss3_platform = config_class == "ToyotaTSS3PlatformConfig"
  secoc_platform = config_class in {"ToyotaSecOCPlatformConfig", "ToyotaTSS3PlatformConfig"} or "ToyotaFlags.SECOC" in block
  check("platform_secoc_enabled", secoc_platform,
        f"config={config_class or 'missing'}; target must carry Toyota SecOC flag")

  effective_dbc = _explicit_dbc(block)
  if effective_dbc is None and config_class == "ToyotaSecOCPlatformConfig":
    effective_dbc = _default_secoc_dbc(values_source)
  if effective_dbc is None and tss3_platform:
    effective_dbc = _default_tss3_dbc(values_source)
  check("dbc_pt_matches", bool(requested_dbc) and requested_dbc == effective_dbc,
        f"reviewed={requested_dbc or 'empty'} source={effective_dbc or 'unresolved'}")
  dbc_source = _dbc_generator_source(root, effective_dbc or "")
  check("dbc_source_present", dbc_source is not None,
        str(dbc_source) if dbc_source else f"generator source for {effective_dbc or 'unresolved'} not found")

  angle_source = tss3_platform or "ToyotaFlags.ANGLE_CONTROL" in block
  expected_angle = steer_control_type == "angle"
  valid_steer_mode = steer_control_type in ("torque", "angle")
  check("steer_control_type_valid", valid_steer_mode, steer_control_type or "empty")
  check("steer_control_type_matches", valid_steer_mode and angle_source == expected_angle,
        f"reviewed={steer_control_type or 'empty'} source={'angle' if angle_source else 'torque'}")

  source_eps_scale = _eps_scale(values_source, platform_name) if valid_platform_name else None
  check("eps_scale_matches", requested_eps_scale is not None and requested_eps_scale == source_eps_scale,
        f"reviewed={fields.get('eps_scale', '')!r} source={source_eps_scale}")

  radar_acc = "ToyotaFlags.RADAR_ACC" in block
  long_valid = longitudinal_control in ALLOWED_LONGITUDINAL_CONTROL
  long_matches = (
    (longitudinal_control == "openpilot_default" and not radar_acc) or
    (longitudinal_control == "stock_default" and radar_acc) or
    (longitudinal_control == "openpilot_alpha" and radar_acc)
  )
  check("longitudinal_control_valid", long_valid,
        longitudinal_control or "empty; expected openpilot_default, stock_default, or openpilot_alpha")
  check("longitudinal_control_matches", long_valid and long_matches,
        f"reviewed={longitudinal_control or 'empty'} source={'RADAR_ACC' if radar_acc else 'camera/default-openpilot-long'}")

  safety_flags = _safety_flag_values(values_source)
  computed_safety = source_eps_scale
  if computed_safety is not None and secoc_platform:
    computed_safety |= safety_flags.get("SECOC", 0)
    if angle_source:
      computed_safety |= safety_flags.get("LTA", 0)
    if longitudinal_control == "stock_default":
      computed_safety |= safety_flags.get("STOCK_LONGITUDINAL", 0)
    if effective_dbc == "toyota_new_mc_pt_generated":
      computed_safety |= safety_flags.get("ALT_BRAKE", 0)
  else:
    computed_safety = None

  tss3_no_output = bool(tss3_platform and "ToyotaFlags.TSS3" in interface_source and "SafetyModel.noOutput" in interface_source)
  production_output_enabled = not tss3_no_output
  check("production_output_enabled", production_output_enabled,
        "Toyota production safety/output path enabled" if production_output_enabled else
        "TSS3 research platform is intentionally SafetyModel.noOutput")
  check("safety_param_matches", production_output_enabled and requested_safety is not None and requested_safety == computed_safety,
        (f"reviewed={fields.get('safety_flags', '')!r} source-derived={computed_safety!r}" if production_output_enabled else
         "no production safetyParam exists while TSS3 remains noOutput"))

  fingerprint_block = _fingerprint_block(fingerprints_source, platform_name) if valid_platform_name else None
  tss3_exact_block = _tss3_exact_fw_block(values_source, platform_name) if valid_platform_name else None
  identity_block = fingerprint_block or tss3_exact_block
  identity_source = "FW_VERSIONS" if fingerprint_block is not None else ("TSS3_EXACT_FW_VERSIONS" if tss3_exact_block is not None else "none")
  check("fingerprint_platform_present", identity_block is not None,
        f"{identity_source} contains CAR.{platform_name}" if identity_block else "platform absent from firmware identity maps")
  exact_eps = bool(app_sw_id and identity_block and app_sw_id in identity_block and "Ecu.eps" in identity_block)
  check("exact_eps_f181_present", exact_eps,
        f"EPS F181 {app_sw_id or 'empty'} is {'present' if exact_eps else 'absent'} in {identity_source}")

  interface_contract = all(token in interface_source for token in (
    "EPS_SCALE[candidate]", "ToyotaSafetyFlags.SECOC", "ToyotaSafetyFlags.LTA",
    "ToyotaSafetyFlags.STOCK_LONGITUDINAL", "ret.openpilotLongitudinalControl",
  ))
  check("toyota_interface_contract_present", interface_contract,
        "source still derives EPS scale, SecOC/LTA/stock-long safety and longitudinal ownership")
  controller_contract = all(token in controller_source for token in (
    "create_steer_command", "create_lta_steer_command_2", "create_accel_command_2", "add_mac",
  ))
  check("toyota_secoc_controller_contract_present", controller_contract,
        "current Toyota sender contains secured LKA/LTA/ACC command paths")

  source_hashes = {
    str(path.relative_to(root)): _sha256(path) for path in required
  }
  if dbc_source is not None:
    source_hashes[str(dbc_source.relative_to(root))] = _sha256(dbc_source)

  return {
    "ready": all(item["passed"] for item in checks),
    "root": str(root),
    "platform_name": platform_name,
    "effective_dbc_pt": effective_dbc,
    "source_eps_scale": source_eps_scale,
    "source_safety_param": computed_safety,
    "source_sha256": source_hashes,
    "checks": checks,
  }
