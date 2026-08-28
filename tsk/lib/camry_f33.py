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
  "state": "passive-read-only",
  "static_receiver_integration": "closed",
  "cpu_visible_key_recovery": "negative",
  "principal_blocker": "live and volatile-runtime architecture gates",
  "output": "disabled",
  "output_detail": "SafetyModel.noOutput; controller emits zero CAN",
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
  "passive_port_baseline_root_commit": "d7d7dfd7e49961e9d35eb7a7681e8756ceee8d04",
  "opendbc_commit": "0d5773bd393bbf3d4109728171d2390b60fcde16",
  "platform": "TOYOTA_CAMRY_TSS3",
  "mode": "passive",
  "safety": "noOutput",
  "controller_can_output": False,
  "exact_f181_binding": True,
}

CAMRY_F33_REMAINING_PRODUCTION_GATES = (
  "relay-correct stock B6 off-active-off capture: cadence, complete 28-byte template, sequence restart, freshness",
  "exclusive stock B6 producer suppression / relay authority",
  "application-context ICU-S slot-4 command-5 general-generation permission and latency/jitter",
  "validated driver-override and motor-current-response policy",
  "live 0x351/0x394/0x4A3 normal/inhibit/fault/recovery transitions",
  "reachable application XCP route plus a concrete reversible volatile control-transfer pivot, if using the RAM-only signer architecture",
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
    "checkpoint": CAMRY_F33_CHECKPOINT,
    "production_architecture": CAMRY_F33_PRODUCTION_ARCHITECTURE,
    "opendbc": CAMRY_F33_OPENDBC,
    "production_output_allowed": False,
    "remaining_production_gates": CAMRY_F33_REMAINING_PRODUCTION_GATES,
  })
