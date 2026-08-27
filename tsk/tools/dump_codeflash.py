#!/usr/bin/env python3
"""CLI for the exact-target 2026 Camry/F33 CodeFlash collector."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Running a copied helper from /cache on AGNOS should still use the active checkout.
if Path("/data/openpilot").is_dir():
  sys.path.insert(0, "/data/openpilot")

from tsk.lib.dump_codeflash import dump


def main() -> int:
  parser = argparse.ArgumentParser(description="Dump exact 8965F3307000 Camry EPS CodeFlash in NRTD")
  parser.add_argument("--output-dir", type=Path)
  parser.add_argument("--resume-dump", type=Path)
  parser.add_argument("--resume-coverage", type=Path)
  args = parser.parse_args()

  result = dump(output_dir=args.output_dir,
                resume_dump=args.resume_dump,
                resume_coverage=args.resume_coverage)
  print(json.dumps(result, indent=2, sort_keys=True))
  return 0 if result.get("status") == "complete" else 10


if __name__ == "__main__":
  raise SystemExit(main())
