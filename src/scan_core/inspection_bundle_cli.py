"""Console entry point for portable Scan Inspection Bundle v1."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .inspection_bundle import create_inspection_bundle, format_bundle_verification, verify_inspection_bundle
from .validate import validate_path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scan-bundle",
        description="Create or verify a deterministic portable Scan Inspection Bundle v1.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="create a bundle from a validated Scan state")
    create.add_argument("state_json", type=Path)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--json", action="store_true")

    verify = subparsers.add_parser("verify", help="verify a bundle without target execution or network access")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--json", action="store_true")

    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command == "create":
        if not args.state_json.is_file():
            parser.error(f"state does not exist: {args.state_json}")
        state = validate_path(args.state_json)
        result = create_inspection_bundle(state, args.output)
        value = result.as_dict()
        if args.json:
            print(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        else:
            print(f"Inspection Bundle created: {result.path}")
            print(f"Bundle: {result.bundle_digest}")
            print(f"State: {result.state_digest}")
            print(f"Handoff: {result.handoff_digest}")
        return 0

    if not args.bundle.is_file():
        parser.error(f"bundle does not exist: {args.bundle}")
    value = verify_inspection_bundle(args.bundle)
    if args.json:
        print(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    else:
        print(format_bundle_verification(value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
