"""Standalone source identity, Python validation and native build commands."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tools.collector_repository.identity import canonical_json


def main(argv: list[str] | None = None) -> int:
    """Execute a local-only standalone repository operation."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("verify", "validate", "native", "security", "provision", "bootstrap"):
        command = commands.add_parser(name)
        command.add_argument("--root", type=Path, default=Path.cwd())
        if name in {"validate", "native", "security", "provision"}:
            command.add_argument("--output", type=Path, required=True)
        if name == "provision":
            command.add_argument("--tools", nargs="+", choices=("gitleaks", "actionlint"), default=["gitleaks"])
    args = parser.parse_args(argv)
    try:
        if args.command in {"bootstrap", "provision"}:
            from tools.collector_repository.toolchain import CiToolchain  # noqa: PLC0415

            if args.command == "bootstrap":
                result = CiToolchain().bootstrap(args.root)
            else:
                CiToolchain().provision(args.root, args.output, args.tools)
                result = {"status": "provisioned", "tools": args.tools}
        elif args.command == "security":
            from tools.collector_repository.security import RepositorySecurityValidator  # noqa: PLC0415

            result = RepositorySecurityValidator().validate(args.root, args.output)
        elif args.command == "verify":
            from tools.collector_repository.identity import RepositoryIdentity  # noqa: PLC0415
            from tools.collector_repository.secrets import GitleaksSecretScanner  # noqa: PLC0415

            result = RepositoryIdentity().verify(args.root)
            GitleaksSecretScanner().scan(args.root)
        else:
            from tools.collector_repository.validation import RepositoryValidator  # noqa: PLC0415

            result = RepositoryValidator().validate(args.root, args.output, native=args.command == "native")
    except (ValueError, OSError, RuntimeError) as exc:
        sys.stderr.write(f"Standalone repository operation failed: {exc}\n")
        return 2
    sys.stdout.write(canonical_json(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
