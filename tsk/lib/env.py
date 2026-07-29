# tsk/lib/env.py
import os
from pathlib import Path

def is_agnos():
  return os.path.exists("/AGNOS")


COMMA_DATA_DIR = "/data" if is_agnos() else f"{os.path.expanduser('~')}/comma_data"

CONTINUE_FILE = f"{COMMA_DATA_DIR}/continue.sh"
OPENPILOT_DIR = f"{COMMA_DATA_DIR}/openpilot"
PAYLOAD_PATH = str(Path(__file__).parent / "payload.bin")
DATAFLASH_PAYLOAD_PATH = str(Path(__file__).parent / "payload_dataflash_ff200000_ff208000.bin")

# CAN messages and DataFlash dumps live under /cache so they survive reboot but
# clear on AGNOS update. Off-device they go under ~/comma_data for dry-run testing.
CACHE_DIR = "/cache" if is_agnos() else f"{COMMA_DATA_DIR}/cache"
DATAFLASH_DIR = f"{CACHE_DIR}/tsk/dataflash"
CAN_MESSAGES_DIR = f"{CACHE_DIR}/tsk/can-messages"
CAN_ORACLE_PATH = f"{CAN_MESSAGES_DIR}/can_oracle.ndjson"

RECOMMENDED_OP_USER = "commaai"
RECOMMENDED_OP_BRANCH = "nightly-dev"
RECOMMENDED_OP_DIR = f"{COMMA_DATA_DIR}/tsk-recommended"
ALTERNATE_OP_USER = "sunnypilot"
ALTERNATE_OP_BRANCH = "staging"
ALTERNATE_OP_DIR = f"{COMMA_DATA_DIR}/tsk-alternate"
