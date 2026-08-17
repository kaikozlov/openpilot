#!/usr/bin/env python3
"""Rebuild TSKM's experimental auto-reset DataFlash payload.

The executable body comes from Vance's pinned candidate-f05 artifact, but that
external ciphertext was authenticated with the bootloader SecurityAccess secret
rather than the analyzed Sienna's normal payload-build secret. This tool recovers
and verifies the external plaintext, preserves its code/CRC region byte-for-byte,
recomputes only the CMAC under PAYLOAD_BUILD_SECRET, and re-encrypts it using the
normal zero-DID201/zero-IV payload scheme.

Inputs are intentionally external to this repository: the analyzed CodeFlash and
the pinned candidate-f05 ciphertext. This keeps provenance explicit and makes the
committed derivative reproducible without embedding firmware secrets in source.
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import struct
import sys
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tsk.lib.ram_exec_geometry import COMMITTED_PAYLOAD_CONTRACT

PAYLOAD_SIZE = COMMITTED_PAYLOAD_CONTRACT.size
CMAC_OFFSET = 0xFF0
CALLBACK_OFFSET = 0xFD0
BODY_END = 0x1B2
ZERO = bytes(16)

SOURCE_CIPHERTEXT_SHA256 = "296d87d2e89b9c7e800122e4c7f6d3b9c876362e52586530cdd53c86ba1116f5"
SOURCE_PLAINTEXT_SHA256 = "ec39ef6c4a19c3687ee59183e2526bdea9e6d4886f11fbe4ab1f5382c484e1c0"
BODY_SHA256 = "5551b5aaecaeb361b21777d2f91d7cdf7b2dfe6b2ec0d1356d544cdbdf3416d1"
OUTPUT_CIPHERTEXT_SHA256 = "bf62449f85648ea24708961749bf53f75f36083c01bcf54114d567da0e178725"


def sha256(data: bytes) -> str:
  return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
  if not condition:
    raise ValueError(message)


def rebuild(codeflash: bytes, source_ciphertext: bytes) -> bytes:
  require(len(source_ciphertext) == PAYLOAD_SIZE, "candidate-f05 payload must be 4096 bytes")
  require(sha256(source_ciphertext) == SOURCE_CIPHERTEXT_SHA256,
          "candidate-f05 ciphertext hash mismatch")
  require(len(codeflash) >= 0xBFF8, "CodeFlash image is too small for payload-gate secrets")

  payload_build_secret = codeflash[0xBFD8:0xBFE8]
  security_access_secret = codeflash[0xBFE8:0xBFF8]
  require(len(payload_build_secret) == 16 and len(security_access_secret) == 16,
          "failed to read 16-byte payload/security secrets")

  source_key = AES.new(security_access_secret, AES.MODE_ECB).encrypt(ZERO)
  source_plain = AES.new(source_key, AES.MODE_CBC, iv=ZERO).decrypt(source_ciphertext)
  require(sha256(source_plain) == SOURCE_PLAINTEXT_SHA256,
          "candidate-f05 plaintext hash mismatch")
  require(sha256(source_plain[:BODY_END]) == BODY_SHA256,
          "candidate-f05 RH850 body hash mismatch")
  require((binascii.crc32(source_plain[:CMAC_OFFSET]) & 0xFFFFFFFF) == 0xFFFFFFFF,
          "candidate-f05 CRC region is invalid")
  require(struct.unpack_from("<I", source_plain, CALLBACK_OFFSET)[0] == COMMITTED_PAYLOAD_CONTRACT.callback_addr,
          "candidate-f05 callback pointer changed")
  require(struct.unpack_from("<II", source_plain, 0xFE0) == (COMMITTED_PAYLOAD_CONTRACT.load_addr, 0xFF0),
          "candidate-f05 CRC descriptor changed")

  normal_key = AES.new(payload_build_secret, AES.MODE_ECB).encrypt(ZERO)
  cmac = CMAC.new(normal_key, ciphermod=AES)
  cmac.update(ZERO + source_plain[:CMAC_OFFSET])
  output_plain = source_plain[:CMAC_OFFSET] + cmac.digest()

  require(output_plain[:CMAC_OFFSET] == source_plain[:CMAC_OFFSET],
          "rebuild changed candidate executable/CRC region")
  require(sha256(output_plain[:BODY_END]) == BODY_SHA256,
          "rebuild changed candidate RH850 body")
  require((binascii.crc32(output_plain[:CMAC_OFFSET]) & 0xFFFFFFFF) == 0xFFFFFFFF,
          "rebuilt CRC region is invalid")

  output_ciphertext = AES.new(normal_key, AES.MODE_CBC, iv=ZERO).encrypt(output_plain)
  require(sha256(output_ciphertext) == OUTPUT_CIPHERTEXT_SHA256,
          "rebuilt ciphertext hash mismatch")
  return output_ciphertext


def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--codeflash", type=Path, required=True,
                      help="Analyzed RH850 CodeFlash containing secrets at 0xBFD8/0xBFE8")
  parser.add_argument("--candidate", type=Path, required=True,
                      help="Pinned raw Vance candidate-f05 ciphertext (SHA-256 296d87d2...)")
  parser.add_argument("--output", type=Path, required=True)
  parser.add_argument("--check", action="store_true",
                      help="Verify an existing output instead of overwriting it")
  args = parser.parse_args()

  rebuilt = rebuild(args.codeflash.read_bytes(), args.candidate.read_bytes())
  if args.check:
    require(args.output.is_file(), f"output does not exist: {args.output}")
    require(args.output.read_bytes() == rebuilt, f"output is stale: {args.output}")
    print(f"[PASS] auto-reset payload is reproducible: {args.output}")
    return 0

  args.output.parent.mkdir(parents=True, exist_ok=True)
  args.output.write_bytes(rebuilt)
  print(f"[OK] wrote {args.output} ({len(rebuilt)} bytes, sha256={sha256(rebuilt)})")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
