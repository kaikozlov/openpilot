"""Evidence-bound facts for the maintainer 2026 Camry / EPS 8965F3307000.

This module is intentionally descriptive and non-enabling.  It mirrors verified
field/static evidence from ghidra_rh850_analysis so TSK can reason about this exact
target without projecting Corolla/Sienna assumptions.  None of the values below
selects a production Toyota safety mode or authorizes B6 transmission.
"""
from __future__ import annotations

from copy import deepcopy


CAMRY_F33_APP_F181 = bytes.fromhex(
  "023839363546333330373030300000000038413331313333303331303000000000"
)
CAMRY_F33_PRIMARY_SW = "8965F3307000"
CAMRY_F33_SECONDARY_SW = "8A3113303100"
CAMRY_F33_BOOT_F181 = b"\x02" + b"!" * 32
CAMRY_F33_ROUTE = {
  "tx": 0x7A1,
  "rx": 0x7A9,
  "tx_bus": 1,
  "rx_bus": 1,
  "elm327_param": 1,
  "semantic_path": "normal-harness",
}

CAMRY_F33_MODULES = {
  "eps": {
    "request": 0x7A1, "response": 0x7A9, "bus": 1,
    "f181": CAMRY_F33_PRIMARY_SW, "secondary_f181": CAMRY_F33_SECONDARY_SW,
    "f18c": "8965033K9011J2740743",
  },
  "frc": {
    "request": 0x792, "response": 0x79A, "bus": 1,
    "f181": "8646F3315000", "f18c": "TN69400026030404235J",
    "part_number_0105": "8646C06091", "swin_1fff": "06000000000000000000",
  },
  "brake_epb": {
    "request": 0x7B0, "response": 0x7B8, "bus": 1,
    "f181": "F152633K0000", "f18c": "8954147040CFC1800985",
    "part_number_0105": "8954147040",
  },
}

CAMRY_F33_READY = {
  "address": 0x51E,
  "length": 8,
  "byte": 0,
  "bit": 7,
  "nrtd": 0,
  "ready": 1,
  "controlled_transition_s": 5.213083,
}
CAMRY_F33_GEAR = {0: "P", 1: "R", 2: "N", 3: "D", 4: "B"}

CAMRY_F33_CRUISE = {
  "frc_dids_positive_nrtd": (0x1202, 0x1901, 0x1905, 0x1906, 0x1912, 0x1914, 0x1918, 0x1928),
  "momentary_switch_carrier": {"address": 0x0FE, "length": 32, "bus": 1, "rate_hz": 33.19},
  "momentary_switch_tuple_bytes": (3, 4, 6, 7),
  "momentary_switch_tuples": {
    "baseline": (0x3F, 0x00, 0xC3, 0x62),
    "main": (0x3F, 0x00, 0xC3, 0x66),
    "res_plus": (0xBF, 0x00, 0x43, 0x62),
    "set_minus": (0x3F, 0x80, 0xC3, 0x22),
    "cancel": (0x3F, 0x40, 0xC3, 0x42),
  },
  "distance_did": 0x1912,
  "distance_candidates": (
    {"address": 0x251, "length": 8, "byte": 5, "from": 0x88, "to": 0x28, "lag_ms": 11.109},
    {"address": 0x5AF, "length": 32, "byte": 24, "from": 0xF0, "to": 0xE4, "lag_ms": 11.760},
  ),
  "brake_102f_readable": True,
  "brake_107e_default_extended": "requestOutOfRange",
}

CAMRY_F33_CODEFLASH = {
  "raw_transport_start": 0x00000000,
  "raw_transport_end": 0x00200000,
  "raw_transport_size": 0x200000,
  "raw_transport_sha256": "b588c7258699beee77669d1f5f09bb17ef8b189b941b46f344a07378c3aaa727",
  "normalized_size": 0x100000,
  "normalized_sha256": "42dce8efc42f6ae31718e7713fa2d26bb9191b4a82439778aee4d7afded9b0e7",
  "upper_half": "all-ff",
  "payload_sha256": "860f8a3418d23ccfd0861a97efdb9e1d23a8854c3a629b8d7b6821eb93d0b588",
  "payload_size": 0x1000,
  "successful_words": 524288,
  "conflicts": 0,
  "duplicates": 0,
  "spi_errors": 0,
  "boot_sid23_codeflash": "rejected",
  "boot_stack": "old",
  "download_base": 0xFEBF0000,
  "download_size": 0x1000,
  "verify_routine": 0x10F0,
  "execute_routine": 0xFF00,
}

# Exact target-native B6 receive/steering contract.  Values are representation
# constraints recovered from firmware, not production driver-override policy.
CAMRY_F33_B6 = {
  "address": 0x0B6,
  "pdu": 44,
  "length": 32,
  "application_length": 28,
  "freshness_bits": 46,
  "transmitted_freshness_bits": 4,
  "full_cmac_bits": 128,
  "transmitted_cmac_bits": 28,
  "crypto_handle": 0,
  "crypto_selector": 4,
  "icus_command": 7,
  "protected_rx_ids": (0x00F, 0x0D7, 0x0B6),
  "target_lateral_id": {"signal": 261, "byte": 3, "mask": 0x3F, "lta_lca": 11},
  "target_steering_angle": {
    "signal": 262, "bytes": (4, 5), "signed_bits": 16,
    "scale_deg_per_count": 1024 / 17870,
    "absolute_max_raw": 1745,
    "delta_max_per_effective_gap_raw": 78,
    "effective_gap_max": 8,
  },
  "sequence": {"signal": 268, "modulus": 64},
  "additive_term_suppress": {"signal": 265, "suppress_value": 1},
  "contribution_percent_signals": (269, 270),
  "foreground_period_ms": 5.0,
  "first_foreground_interval_ms": 5.125,
  "nominal_rx_timeout_ms": 35.0,
  "steering_angle_velocity": {"signal": 189, "did": 0x1036, "abs_raw_monitor": 100, "persistence_cycles": 79},
  "steering_wheel_torque": {"did": 0x1035, "scale_nm_per_raw": 1 / 256, "acquisition_clamp_raw": 2109},
  "motor_q_current": {"did": 0x1151, "formula": "raw*100/0x80"},
}

# Secured-looking lateral request representation recovered from the two relay-correct drives
# (ghidra_rh850_analysis VAR-081 / CORR-134).  This is observed representation
# only: the producer is unknown and 0x08A is NOT exact-F33 ingress.
CAMRY_F33_LATERAL_REQUEST = {
  "address": 0x08A,
  "length": 32,
  "target_steering_angle": {"bytes": (18, 19), "signed_bits": 16,
                            "scale_deg_per_count": 1024 / 17870},
  "target_lateral_id": {"byte": 21, "observed": (0, 11, 18)},
  "sequence": {"byte": 26, "modulus": 64},
  "security_trailer": {
    "candidate_layout": "B28[7:6]=message_low2, B28[5:4]=reset_low2, B28[3:0]+B29:B31=authenticator28",
    "classification": "strong Toyota P5 ordinary-SecOC structural match; exact sender profile/key/CMAC not recovered",
    "reset_low2_match": {"drive_a": (19868, 20615), "drive_b": (23093, 23996)},
    "same_reset_sequence_pairs_message_plus1": {"drive_a": (18727, 18727), "drive_b": (21989, 21989)},
  },
  "manual_id0_angle_scale_fit": {"drive_a": 0.05731251, "drive_b": 0.05731821,
                                 "scale_error_pct": (0.017046, 0.026993)},
  "observed_buses": {"panda_bus0": 44614, "relay_mirror_bus2": 44617, "panda_bus1": 0},
  "encoding_caveat": (
    "B21/B26 upper two bits are zero in all 89,231 retained frames "
    + "and the GTS+ diagnostic field is 8-bit, so 6-bit field boundaries are encoding assumptions"
  ),
  "producer": (
    "unknown; every retained frame is on the Bus-4 Brake/EPS capture, "
    + "not the Front-Camera Bus-1 topology segment"
  ),
  "eps_ingress": False,
  "eps_generated_com_transmit": False,
  "stock_lta_requires_b6": False,
  "boundary": (
    "0x08A ownership/security and exact-F33 stock-LTA authority selection are separate "
    + "questions; no 0x08A-to-B6 transform is established or required"
  ),
}

CAMRY_F33_RAM_RECOVERY = {
  "dataflash": {
    "start": 0xFF200000, "end": 0xFF208000,
    "sha256": "231fbdde5e149c0d7151b12818c3df2dfac159f98418887ba0015f31e6774432",
  },
  "local_ram_pe1": {
    "start": 0xFEBE0000, "end": 0xFEC00000,
    "sha256": "0ddef478df64cde3071301750ab44c79373d0e6ec9f831cc1300494b31235a7",
    "boot_payload_clobber": (0xFEBF0000, 0xFEBF1000),
  },
  "global_ram": {
    "start": 0xFEEF8000, "end": 0xFEF08000,
    "sha256": "53c83702ec5d01b686159c871280847f5345a38bc57ca1573d1de31b54206a4",
  },
  "dataflash_object15_valid_copies": 0,
  "dataflash_object15_key_fields": "zero16",
  "legacy_ram_key_table_valid_records": 0,
  "application_sa_root_address": 0xFEBF7B80,
  "raw_key_scan_survivors": 0,
  "boundary": "post-application-to-boot RAM; opaque ICU-S slot-4 key remains compatible with the negative CPU-visible scan",
}

CAMRY_F33_TX_STATUS = {
  "first_five_tx_pdus": (0x030, 0x351, 0x394, 0x4A3, 0x4C8),
  "packers": {
    0x351: 0x4CED0,
    0x394: 0x4CE08,
    0x4A3: (0x4C000, 0x4C14E, 0x4C7AA),
  },
  "driver_torque_direct_references": {"total": 9, "reads": 7, "writes": 2},
  "motor_q_current_direct_references": {"total": 6, "reads": 4, "writes": 2},
  "can_4a3_alternate_current_source_direct_references": 4,
  "torque_telemetry_producer": 0x4C000,
  "cooperative_control_cone_direct_torque_refs": 0,
  "can_4a3_b6_b7_source_gp_offset": -0x50E8,
  "did_1151_q_current_source_gp_offset": -0x50F2,
  "can_4a3_b6_b7_is_did_1151_q_current": False,
}

# Exact F33 0x394 projection of the internal 17-row state table at CodeFlash
# 0x2A19C.  The wire omits table column 0; two tuples are therefore lossy.
# These are internal classifier candidates only, not openpilot fault policy.
CAMRY_F33_EPS_394_STATE_CANDIDATES = {
  (0, 0, 0, 0): (0,),
  (0, 3, 0, 0): (1, 3, 4),
  (0, 7, 0, 0): (2, 16),
  (0, 1, 0, 0): (5,),
  (2, 3, 2, 1): (6,),
  (0, 3, 2, 1): (7,),
  (2, 3, 3, 0): (8,),
  (0, 3, 3, 0): (9,),
  (1, 7, 1, 1): (10,),
  (1, 7, 4, 1): (11,),
  (1, 7, 7, 0): (12,),
  (1, 7, 6, 0): (13,),
  (1, 7, 5, 0): (14,),
  (0, 2, 0, 0): (15,),
}

CAMRY_F33_APPLICATION_RUNTIME = {
  "low_boot_staging_retained_after_stock_startup": False,
  "retained_exec_tail_start": 0xFEBFF9F0,
  "retained_exec_tail_end_inclusive": 0xFEBFFBFB,
  "retained_exec_tail_size": 524,
  "retained_exec_tail_sha256": "89ffed31c24e746a57171e6f3e22f99d1e78d57b63bccb8778c7fe715d18800c",
  "xcp_request": 0x7F7,
  "xcp_response": 0x7F8,
  "xcp_callbacks": {
    "set_mta": 0x82C62,
    "download": 0x81FFE,
    "modify_bits": 0x820C4,
    "short_upload": 0x82B1A,
    "write_validator": 0x98F2C,
  },
  "xcp_write_window": (0xFEBF7C00, 0xFEBFFBFF),
  "xcp_connect_bus1_elm1": "timeout",
  "rid_100f_reaches_command5": True,
  "rid_100f_general_secoc_signer": False,
  "application_write_memory_by_address_3d": False,
  "application_control_transfer_into_tail": "not-recovered",
  "fixed_dmac_endpoint_fields_checked": 88,
  "fixed_dmac_endpoints_in_xcp_window": 0,
}

CAMRY_F33_CHECKPOINT = {
  "target": "2026 Camry / F33",
  "state": "normal-port-supported-patched-eps",
  "static_receiver_integration": "closed",
  "cpu_visible_key_recovery": "negative",
  "key_storage": "ICU-S-protected-slot-4-not-ordinary-dataflash",
  "unsupported_feature": (
    "openpilot-generated stock-ACC cancel has no recovered TSS3 transmit contract; physical CANCEL "
    + "is decoded normally and no protected switch or acceleration frame is spoofed"
  ),
  "factory_architecture_open": (
    "FRC request transport and exact always-on 0x08A protected publisher remain unresolved "
    + "but do not block direct B6 actuation"
  ),
  "output": "exact-F33-normal-port",
  "output_detail": (
    "Ordinary CarParams/CarController/Panda safety on TOYOTA_CAMRY_TSS3. Zero-MAC28 B6 is "
    + "accepted because this maintainer EPS carries the persistent Gate-2 patch; no key and no "
    + "RAM bridge are involved. This is custom exact-target support, not an upstream Toyota key-backed path."
  ),
}

CAMRY_F33_LATERAL_PORT = {
  "available": True,
  "status": "native-port-gate2-patched-eps",
  "superseded": (
    "the private-parameter/ephemeral-bridge/ALLOW_DEBUG arming path (ToyotaEphemeralSecOCBridge, "
    + "ToyotaEphemeralSecOCBridgeF181, ToyotaTss3DevLateral, ToyotaTSS3FrcOracleCapture) is removed; "
    + "the port now follows the ordinary Toyota/openpilot shape"
  ),
  "engagement": (
    "ordinary openpilot lateral engagement (CC.latActive); no private arming parameters and no "
    + "SecOC-key availability state"
  ),
  "sender": (
    "one zero-MAC28 0x0B6/DLC32 frame per scheduled control frame on Panda bus 0; live "
    + "SECOC_SYNCHRONIZATION (0x00F) TRIP/RESET freshness; ID11 while active, ID0 with zeroed "
    + "companions on release; standard angle-rate-limited target angle"
  ),
  "safety": (
    "ordinary SafetyModel.toyota with EPS_SCALE|STOCK_LONGITUDINAL|TSS3 (not ALLOW_DEBUG); TSS3 "
    + "branch TX-whitelists only 0x0B6 bus0 DLC32 with relay check; controls_allowed from 0x08A "
    + "bit 27 on bus 2; target ID 0/11 only, companion percentages <=100 and zero when inactive, "
    + "steer_angle_cmd_checks at +/-1745 raw with standard rate limits"
  ),
  "receiver_acceptance": (
    "zero-MAC28 B6 is accepted because this maintainer EPS carries the persistent exact-F33 "
    + "Gate-2 patch (CodeFlash compare neutralization with deterministic CRC repair); this does "
    + "not recover or replace the protected key"
  ),
  "unsupported_features": (
    "openpilot-generated stock-ACC cancel is unsupported until its exact TSS3 transmit contract is recovered; "
    + "driver-override threshold and openpilot temporary/permanent EPS-fault classes remain intentionally unmapped"
  ),
  "companion_boundary": "no stock B6 was retained; unresolved application bytes remain explicit zero/default candidates rather than Toyota stock claims",
  "supported_output": True,
}

CAMRY_F33_PRODUCTION_ARCHITECTURE = {
  "status": "preferred-volatile-application-runtime",
  "ready": False,
  "runtime_model": "RAM-only / reset-to-stock",
  "preferred_path": "application XCP DOWNLOAD plus a reversible volatile control-transfer pivot",
  "persistent_flash": "fallback-only",
  "ranking": (
    {
      "rank": 1,
      "path": "application XCP DOWNLOAD plus a reversible volatile control-transfer pivot",
      "status": "preferred-blocked",
    },
    {
      "rank": 2,
      "path": "RID 0x100F command-5 permission and hardware oracle",
      "status": "oracle-only-not-general-signer",
    },
    {
      "rank": 3,
      "path": "PROGRAMMING loader",
      "status": "research-and-acquisition-only",
    },
    {
      "rank": 4,
      "path": "persistent flash hook",
      "status": "fallback-only",
    },
  ),
}

CAMRY_F33_OPENDBC = {
  "platform": "TOYOTA_CAMRY_TSS3",
  "mode": "normal-port; ordinary CarParams + CarController + Panda safety; no private parameters",
  "safety": "SafetyModel.toyota with EPS_SCALE|STOCK_LONGITUDINAL|TSS3; TSS3 branch TX-whitelists only 0x0B6 bus0 DLC32",
  "controller_can_output": True,
  "supported_output": True,
  "exact_f181_binding": True,
  "lateral_request_decoding": True,
}

CAMRY_F33_REMAINING_RESEARCH_BOUNDARIES = (
  "openpilot-generated stock-ACC cancel transmit contract is not recovered; do not spoof 0x0FE/0x0C9/0x0CA",
  "driver-override threshold is not recovered; physical driver torque remains observational",
  "openpilot temporary/permanent EPS-fault classification is not recovered; physical status remains observational",
  "0x08A producer/private-middle stock-authority attribution remains research-only and does not gate B6 output",
  "RAM-only/reset-to-stock signer remains future research to replace the already-verified persistent Gate-2 patch",
)

def public_camry_f33_status() -> dict:
  """Return a JSON-friendly copy of the exact-target evidence checkpoint."""
  return deepcopy({
    "application_f181_hex": CAMRY_F33_APP_F181.hex(),
    "primary_software_id": CAMRY_F33_PRIMARY_SW,
    "secondary_software_id": CAMRY_F33_SECONDARY_SW,
    "route": CAMRY_F33_ROUTE,
    "modules": CAMRY_F33_MODULES,
    "ready": CAMRY_F33_READY,
    "gear": CAMRY_F33_GEAR,
    "cruise": CAMRY_F33_CRUISE,
    "tx_status": CAMRY_F33_TX_STATUS,
    "codeflash": CAMRY_F33_CODEFLASH,
    "b6": CAMRY_F33_B6,
    "ram_recovery": CAMRY_F33_RAM_RECOVERY,
    "eps_394_state_candidates": CAMRY_F33_EPS_394_STATE_CANDIDATES,
    "application_runtime": CAMRY_F33_APPLICATION_RUNTIME,
    "lateral_request": CAMRY_F33_LATERAL_REQUEST,
    "checkpoint": CAMRY_F33_CHECKPOINT,
    "lateral_port": CAMRY_F33_LATERAL_PORT,
    "production_architecture": CAMRY_F33_PRODUCTION_ARCHITECTURE,
    "opendbc": CAMRY_F33_OPENDBC,
    "supported_output": True,
    "remaining_research_boundaries": CAMRY_F33_REMAINING_RESEARCH_BOUNDARIES,
  })
