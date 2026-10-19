"""Standalone source identity, Python validation and native build commands."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tools.collector_repository.identity import canonical_json


def _positive_workers(value: str) -> int:
    workers = int(value)
    if workers < 1:
        message = "pytest workers must be positive"
        raise argparse.ArgumentTypeError(message)
    return workers


def main(argv: list[str] | None = None) -> int:
    """Execute a local-only standalone repository operation."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("verify", "validate", "native", "security", "provision", "bootstrap"):
        command = commands.add_parser(name)
        command.add_argument("--root", type=Path, default=Path.cwd())
        if name in {"validate", "native", "security", "provision"}:
            command.add_argument("--output", type=Path, required=True)
        if name in {"validate", "native"}:
            command.add_argument("--source-sha")
            command.add_argument(
                "--pytest-workers", type=_positive_workers, default=1, help="Source pytest processes (default: serial); all standalone tests remain selected."
            )
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

            result = RepositoryValidator().validate(
                args.root,
                args.output,
                native=args.command == "native",
                source_sha=args.source_sha,
                pytest_workers=args.pytest_workers,
            )
    except (ValueError, OSError, RuntimeError) as exc:
        sys.stderr.write(f"Standalone repository operation failed: {exc}\n")
        return 2
    sys.stdout.write(canonical_json(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
