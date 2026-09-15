"""Generate and verify platform-owned native dependency hash locks."""

# ruff: noqa: C901, EM101, EM102, FBT001, S607, TRY003
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import cast

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

PYTHON_VERSION = "3.12.10"
PIP_TOOLS_VERSION = "7.6.1"
LOCK_TARGETS = (
    "windows-x86_64",
    "linux-x86_64",
    "macos-x86_64",
    "macos-arm64",
)
TARGET_ONLY_PACKAGES = {
    "macholib": frozenset({"macos-x86_64", "macos-arm64"}),
    "pefile": frozenset({"windows-x86_64"}),
    "pywin32-ctypes": frozenset({"windows-x86_64"}),
}
_PIN = re.compile(r"^[A-Za-z0-9_.-]+==[^ ;\\]+")
_HEADER = re.compile(r"^# Unio Collector native hash lock: (?P<target>[a-z0-9_-]+)$")
_ABSOLUTE_WINDOWS_PATH = re.compile(r"(?i)(?:^|[ (])(?:[a-z]:[/\\]|\\\\)")
_ABSOLUTE_POSIX_PROVENANCE = re.compile(r"(?i)(?:file:(?:/{1,3}|[a-z]:)|(?:via|-r)\s+/)")
SHA256_HEX_LENGTH = 64


def main() -> int:
    """Generate, byte-check, or consolidate native locks."""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("generate", "check"):
        target_parser = subparsers.add_parser(command)
        target_parser.add_argument("--target", choices=LOCK_TARGETS, default=None)
        target_parser.add_argument("--upgrade", action="store_true")
        target_parser.add_argument("--evidence", type=Path, default=None)
        target_parser.add_argument("--source-sha", default=None)
    validate_set = subparsers.add_parser("validate-set")
    validate_set.add_argument("--artifact-root", type=Path, required=True)
    validate_set.add_argument("--source-sha", required=True)
    validate_set.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    _require_toolchain()
    if args.command == "validate-set":
        validate_artifact_set(args.artifact_root, args.source_sha, args.destination)
        return 0

    root = Path(__file__).resolve().parents[1]
    host_target = current_target()
    target = args.target or host_target
    if target != host_target:
        raise SystemExit(f"Native lock {target} must be generated on its matching {host_target} host.")
    destination = root / "requirements" / f"native-{target}.lock"
    with tempfile.TemporaryDirectory(prefix="unio-collector-native-lock-") as raw:
        workspace = Path(raw)
        candidate = workspace / destination.name
        if destination.is_file() and not args.upgrade:
            shutil.copy2(destination, candidate)
        _compile(root, workspace, candidate, target, args.upgrade)
        validate_lock(candidate, expected_target=target, require_host=True)
        if args.command == "check":
            if not destination.is_file() or not _lock_contents_equal(candidate, destination):
                raise SystemExit(f"Native dependency lock drifted: {destination.name}")
        else:
            destination.write_bytes(candidate.read_bytes())
        if args.evidence is not None:
            write_provenance(
                args.evidence,
                candidate,
                source_sha=args.source_sha or _source_sha(root),
                target=target,
            )
    return 0


def current_target() -> str:
    """Return the normalized current native lock target."""
    system = {"darwin": "macos"}.get(platform.system().casefold(), platform.system().casefold())
    machine = {"amd64": "x86_64", "aarch64": "arm64"}.get(
        platform.machine().casefold(),
        platform.machine().casefold(),
    )
    return f"{system}-{machine}"


def validate_lock(
    path: Path,
    *,
    expected_target: str | None = None,
    require_host: bool = False,
) -> None:
    """Require target identity, platform purity, exact pins, and hashes."""
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    match = _HEADER.match(lines[0] if lines else "")
    if match is None:
        raise ValueError(f"Native dependency lock has no valid target header: {path}")
    target = match.group("target")
    if target not in LOCK_TARGETS:
        raise ValueError(f"Native dependency lock has an unknown target: {target}")
    filename_target = path.name.removeprefix("native-").removesuffix(".lock")
    if path.name.startswith("native-") and filename_target != target:
        raise ValueError(f"Native dependency lock filename/header mismatch: {path}")
    if expected_target is not None and target != expected_target:
        raise ValueError(f"Native dependency lock target mismatch: expected {expected_target}, found {target}")
    if require_host and target != current_target():
        raise ValueError(f"Native dependency lock {target} does not match host {current_target()}.")
    if _ABSOLUTE_WINDOWS_PATH.search(text) or _ABSOLUTE_POSIX_PROVENANCE.search(text):
        raise ValueError(f"Native dependency lock contains machine-specific provenance: {path}")

    logical = _logical_requirements(lines)
    if not logical:
        raise ValueError(f"Native dependency lock is empty: {path}")
    packages: set[str] = set()
    for requirement in logical:
        if not _PIN.match(requirement):
            raise ValueError(f"Native dependency is not exact-pinned: {requirement}")
        hashes = re.findall(r"--hash=sha256:([0-9a-fA-F]+)", requirement)
        if not hashes or any(len(digest) != SHA256_HEX_LENGTH for digest in hashes):
            raise ValueError(f"Native dependency has a missing or malformed SHA-256 hash: {requirement}")
        packages.add(canonicalize_name(requirement.split("==", maxsplit=1)[0]))
    for package, allowed_targets in TARGET_ONLY_PACKAGES.items():
        if package in packages and target not in allowed_targets:
            raise ValueError(f"Native dependency {package} is inappropriate for target {target}.")


def lock_sha256(path: Path) -> str:
    """Return the byte-exact lock identity used by protected evidence."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _lock_contents_equal(first: Path, second: Path) -> bool:
    """Compare lock text without platform checkout newline conversion."""
    return first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")


def write_provenance(path: Path, lock: Path, *, source_sha: str, target: str) -> None:
    """Write non-secret native-runner identity evidence for consolidation."""
    payload = {
        "architecture": target.split("-", maxsplit=1)[1],
        "lock_filename": lock.name,
        "lock_sha256": lock_sha256(lock),
        "operating_system": target.split("-", maxsplit=1)[0],
        "pip_tools_version": distribution_version("pip-tools"),
        "python_version": platform.python_version(),
        "schema_version": "2026-08-native-lock-provenance-v1",
        "source_sha": source_sha,
        "target": target,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_artifact_set(artifact_root: Path, source_sha: str, destination: Path) -> None:
    """Validate exactly four native runner results before copying locks."""
    discovered = {path.name.removeprefix("native-lock-") for path in artifact_root.iterdir() if path.is_dir() and path.name.startswith("native-lock-")}
    if discovered != set(LOCK_TARGETS):
        raise ValueError("Native lock artifact set is missing, duplicated, or contains an unknown target.")
    destination.mkdir(parents=True, exist_ok=True)
    for target in LOCK_TARGETS:
        root = artifact_root / f"native-lock-{target}"
        lock = root / f"native-{target}.lock"
        evidence = root / f"native-{target}.provenance.json"
        if not lock.is_file() or not evidence.is_file():
            raise ValueError(f"Native lock artifact is incomplete: {target}")
        validate_lock(lock, expected_target=target)
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        expected = {
            "architecture": target.split("-", maxsplit=1)[1],
            "lock_filename": lock.name,
            "lock_sha256": lock_sha256(lock),
            "operating_system": target.split("-", maxsplit=1)[0],
            "pip_tools_version": PIP_TOOLS_VERSION,
            "python_version": PYTHON_VERSION,
            "source_sha": source_sha,
            "target": target,
        }
        if any(payload.get(key) != value for key, value in expected.items()):
            raise ValueError(f"Native lock provenance does not match target {target}.")
        shutil.copy2(lock, destination / lock.name)


def _compile(root: Path, workspace: Path, candidate: Path, target: str, upgrade: bool) -> None:
    runtime_input = workspace / "unio-collector-runtime.in"
    native_input = workspace / "unio-collector-native-build.in"
    compile_input = workspace / "unio-collector-native.in"
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    runtime = tuple(str(item) for item in project["project"]["dependencies"])
    native = tuple(str(item) for item in project["project"]["optional-dependencies"]["native-build"])
    runtime_input.write_text(_active_requirements(runtime, target), encoding="utf-8", newline="\n")
    native_input.write_text(_active_requirements(native, target), encoding="utf-8", newline="\n")
    compile_input.write_text("-r unio-collector-runtime.in\n-r unio-collector-native-build.in\n", encoding="utf-8", newline="\n")
    command = [
        sys.executable,
        "-m",
        "piptools",
        "compile",
        "--generate-hashes",
        "--resolver=backtracking",
        "--strip-extras",
        "--allow-unsafe",
        "--pip-args=--only-binary=:all:",
        "--no-header",
        "--output-file",
        str(candidate),
    ]
    if upgrade:
        command.append("--upgrade")
    command.append(str(compile_input))
    subprocess.run(command, cwd=workspace, check=True)  # noqa: S603
    _normalize_lock(candidate, workspace, target)
    _validate_inputs(project)


def _active_requirements(requirements: tuple[str, ...], target: str) -> str:
    environment = default_environment()
    operating_system, architecture = target.split("-", maxsplit=1)
    machines = {"x86_64": "AMD64" if operating_system == "windows" else "x86_64", "arm64": "arm64"}
    environment.update(
        {
            "platform_machine": machines[architecture],
            "platform_system": {"windows": "Windows", "linux": "Linux", "macos": "Darwin"}[operating_system],
            "sys_platform": {"windows": "win32", "linux": "linux", "macos": "darwin"}[operating_system],
        },
    )
    active: list[str] = []
    for raw in requirements:
        requirement = Requirement(raw)
        marker_environment = cast("dict[str, str]", environment)
        if requirement.marker is not None and not requirement.marker.evaluate(marker_environment):
            continue
        extras = f"[{','.join(sorted(requirement.extras))}]" if requirement.extras else ""
        value = f"{requirement.name}{extras}{requirement.specifier}"
        if requirement.url:
            value = f"{requirement.name}{extras} @ {requirement.url}"
        active.append(value)
    return "".join(f"{item}\n" for item in sorted(active, key=str.casefold))


def _normalize_lock(candidate: Path, workspace: Path, target: str) -> None:
    text = candidate.read_text(encoding="utf-8").replace("\r\n", "\n")
    variants = {str(workspace), workspace.as_posix(), str(workspace).replace("\\", "/")}
    labels = {
        "unio-collector-runtime.in": "unio-collector runtime",
        "unio-collector-native-build.in": "unio-collector native-build",
        "unio-collector-native.in": "unio-collector native lock input",
    }
    for root in sorted(variants, key=len, reverse=True):
        for filename, label in labels.items():
            text = text.replace(root + "/" + filename, label)
            text = text.replace(root + "\\" + filename, label)
    for filename, label in labels.items():
        text = re.sub(
            rf"(?i)(?:[a-z]:[\\/]|/)[^\r\n]*?[\\/]{re.escape(filename)}",
            label,
            text,
        )
    text = text.replace("-r unio-collector runtime", "unio-collector runtime")
    text = text.replace("-r unio-collector native-build", "unio-collector native-build")
    body = "\n".join(line for line in text.splitlines() if not line.startswith("# Unio Collector native hash lock:"))
    header = (
        f"# Unio Collector native hash lock: {target}\n"
        f"# Generated with Python {PYTHON_VERSION} and pip-tools {PIP_TOOLS_VERSION}.\n"
        "# Inputs: unio-collector runtime dependencies and active target-native build dependencies.\n"
    )
    candidate.write_text(header + body.lstrip("\n") + "\n", encoding="utf-8", newline="\n")


def _logical_requirements(lines: list[str]) -> list[str]:
    logical: list[str] = []
    pending = ""
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith(("#", "--index-url", "--only-binary", "--trusted-host")):
            continue
        pending += line.removesuffix("\\").strip() + " "
        if not line.endswith("\\"):
            logical.append(pending.strip())
            pending = ""
    if pending:
        logical.append(pending.strip())
    return logical


def _validate_inputs(project: dict[str, object]) -> None:
    native_dependencies = project["project"]["optional-dependencies"]["native-build"]  # type: ignore[index]
    if "PyInstaller==6.22.2" not in native_dependencies:
        raise ValueError("Native manifest and lock inputs disagree on PyInstaller.")


def _require_toolchain() -> None:
    if platform.python_version() != PYTHON_VERSION:
        raise SystemExit(f"Native locks require Python {PYTHON_VERSION}.")
    if distribution_version("pip-tools") != PIP_TOOLS_VERSION:
        raise SystemExit(f"Native locks require pip-tools {PIP_TOOLS_VERSION}.")


def _source_sha(root: Path) -> str:
    completed = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


if __name__ == "__main__":
    raise SystemExit(main())
