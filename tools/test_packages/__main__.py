"""Unsigned test retention CLI; local selection requires isolated trusted execution."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tools.test_packages.api import GitHubReadClient

ROOT = Path(__file__).resolve().parents[2]


def _bootstrap_git() -> str:
    """Resolve Git with stdlib before any local import or untrusted CWD lookup."""
    cwd = Path.cwd().resolve()
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        directory = Path(entry)
        if not directory.is_absolute():
            continue
        directory = directory.resolve()
        if directory in (cwd, ROOT) or directory.is_relative_to(cwd) or directory.is_relative_to(ROOT):
            continue
        executable = directory / ("git.exe" if os.name == "nt" else "git")
        if executable.is_file() and not executable.is_symlink() and os.access(executable, os.X_OK):
            return str(executable)
    message = "Existing host Git is unavailable."
    raise ValueError(message)


def _parser() -> argparse.ArgumentParser:
    """Define additive unsigned test retention commands."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("request", "approve", "seal", "select"):
        command = commands.add_parser(name)
        command.add_argument("--repository", required=True)
        if name == "request":
            command.add_argument("--event", type=Path, required=True)
            command.add_argument("--output", type=Path, required=True)
            command.add_argument("--control-sha", required=True)
        elif name in {"approve", "seal"}:
            command.add_argument("--request", type=Path, required=True)
            if name == "seal":
                command.add_argument("--validation", type=Path, required=True)
                command.add_argument("--sources", type=Path, required=True)
                command.add_argument("--target", required=True)
                command.add_argument("--output", type=Path, required=True)
        else:
            command.add_argument("--trusted-source-sha", required=True)
            command.add_argument("--run-id", type=int, required=True)
            command.add_argument("--attempt", type=int, required=True)
            command.add_argument("--python-run-id", type=int, required=True)
            command.add_argument("--security-run-id", type=int, required=True)
            command.add_argument("--output-parent", type=Path, required=True)
    return parser


def main() -> int:
    """Bootstrap only from the explicitly selected local checkout, never an artifact."""
    parser = _parser()
    args = parser.parse_args()
    if not sys.flags.isolated:
        parser.error("Use python -I -B with the absolute path to this reviewed __main__.py.")
    if args.command == "select":
        actual = subprocess.check_output([_bootstrap_git(), "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()  # noqa: S603
        status = subprocess.check_output([_bootstrap_git(), "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, text=True).strip()  # noqa: S603
        ignored = subprocess.check_output([_bootstrap_git(), "ls-files", "--others", "--ignored", "--exclude-standard"], cwd=ROOT, text=True).splitlines()  # noqa: S603
        if any(name.casefold().endswith((".py", ".pyc", ".pyd", ".dll", ".exe")) for name in ignored):
            parser.error("Ignored executable code in selector source.")
        if re.fullmatch(r"[a-f0-9]{40}", args.trusted_source_sha) is None or actual != args.trusted_source_sha or status:
            parser.error("Selector source must be the explicitly reviewed clean commit.")

    sys.path.insert(0, str(ROOT))
    from tools.collector_repository.identity import canonical_json, read_json  # noqa: PLC0415
    from tools.test_packages.api import GitHubReadClient  # noqa: PLC0415
    from tools.test_packages.workflow import RetentionWorkflow  # noqa: PLC0415

    try:
        api = GitHubReadClient(args.repository)
        if args.command == "select":
            from tools.test_packages.selector import TestPackageSelector  # noqa: PLC0415

            selected = TestPackageSelector(ROOT, api).select(
                args.trusted_source_sha, args.run_id, args.attempt, args.output_parent, {"python": args.python_run_id, "security": args.security_run_id}
            )
            result = {"status": "verified-for-manual-testing", "directory": str(selected)}
        elif args.command == "request":
            result = RetentionWorkflow(api, ROOT).request(args.event, args.output, args.control_sha)
        else:
            request = read_json(args.request)
            result = RetentionWorkflow(api, ROOT).approve(request) if args.command == "approve" else _seal(api, request, args)
        sys.stdout.write(canonical_json(result).decode())
    except (ValueError, OSError, RuntimeError, KeyError, TypeError, StopIteration) as exc:
        sys.stderr.write(f"Unsigned test-package operation rejected: {exc}\n")
        return 2
    return 0


def _seal(api: GitHubReadClient, request: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    """Recheck real approval before copying any candidate packages."""
    from tools.collector_repository.paths import require  # noqa: PLC0415
    from tools.test_packages.approval import RetentionApproval  # noqa: PLC0415
    from tools.test_packages.context import TARGETS  # noqa: PLC0415
    from tools.test_packages.packet import TestPackagePacket  # noqa: PLC0415

    context = request["context"]
    require(
        context["run_id"] == int(os.environ["GITHUB_RUN_ID"])
        and context["attempt"] == int(os.environ["GITHUB_RUN_ATTEMPT"])
        and context["checkout"] == os.environ["GITHUB_SHA"],
        "Sealing candidate mismatch.",
    )
    RetentionApproval(api).verify(context, request["environment"])
    runner, _workers = TARGETS[args.target]
    jobs = api.rows(f"actions/runs/{context['run_id']}/attempts/{context['attempt']}/jobs", "jobs")
    jobs = [j for j in jobs if j["name"] == f"native ({runner}, {args.target})" and j["run_attempt"] == context["attempt"] and j["status"] == "in_progress"]
    require(len(jobs) == 1, "Ambiguous native producer job.")
    return TestPackagePacket().seal(ROOT, args.validation, args.sources, request, args.target, jobs[0]["id"], args.output)


if __name__ == "__main__":
    raise SystemExit(main())
