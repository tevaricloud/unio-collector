"""Malware-scan native collector payloads and installers with the host scanner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path


def main() -> int:
    """Scan all requested native release paths and retain a machine-readable result."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append", type=Path, required=True)
    parser.add_argument("--summary-output", type=Path, required=True)
    parser.add_argument("--require-scanner", action="store_true")
    parser.add_argument("--version", default=None)
    parser.add_argument("--source-commit", default=None)
    parser.add_argument("--native-target", default=None)
    args = parser.parse_args()
    scanner = _scanner_command()
    summary = args.summary_output.resolve()
    summary.parent.mkdir(parents=True, exist_ok=True)
    if scanner is None:
        payload = {
            "evidence_status": "unavailable",
            "scanner": None,
            "status": "unavailable",
            "targets": [str(path.resolve()) for path in args.target],
        }
        summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 1 if args.require_scanner else 0
    results: list[dict[str, object]] = []
    for target in args.target:
        resolved = target.resolve()
        if not resolved.exists():
            message = f"Native malware scan target does not exist: {resolved}"
            raise SystemExit(message)
        completed = subprocess.run((*scanner, str(resolved)), check=False, capture_output=True, text=True)  # noqa: S603
        results.append(
            {
                "exit_code": completed.returncode,
                "status": "clean" if completed.returncode == 0 else "quarantined_for_review",
                "target": str(resolved),
            }
        )
    status = "clean" if all(item["exit_code"] == 0 for item in results) else "quarantined_for_review"
    artifact_hashes: dict[str, str] = {}
    for target in args.target:
        resolved = target.resolve()
        if resolved.is_file():
            artifact_hashes[resolved.name] = _sha256(resolved)
            continue
        manifest = resolved / "native-release-manifest.json"
        if manifest.is_file():
            payload_hashes = json.loads(manifest.read_text(encoding="utf-8")).get("artifact_hashes", {})
            if isinstance(payload_hashes, dict):
                artifact_hashes.update({str(name): str(digest) for name, digest in payload_hashes.items()})
    payload = {
        "artifact_hashes": artifact_hashes,
        "evidence_status": "passed" if status == "clean" else "failed",
        "results": results,
        "scanner": scanner[0],
        "source_commit": args.source_commit,
        "status": status,
        "target": args.native_target,
        "version": args.version,
    }
    summary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if status == "clean" else 1


def _scanner_command() -> tuple[str, ...] | None:
    if platform.system().casefold() == "windows":
        candidates: list[Path] = []
        program_files = os.getenv("PROGRAMFILES", "")
        program_data = os.getenv("PROGRAMDATA", "")
        if program_files:
            candidates.append(Path(program_files) / "Windows Defender" / "MpCmdRun.exe")
        if program_data:
            platform_root = Path(program_data) / "Microsoft" / "Windows Defender" / "Platform"
            candidates.extend(sorted(platform_root.glob("*/MpCmdRun.exe"), reverse=True))
        executable = next((path for path in candidates if path.is_file()), None)
        if executable is None:
            return None
        return (str(executable), "-Scan", "-ScanType", "3", "-File")
    clamscan = shutil.which("clamscan")
    if clamscan is None:
        return None
    database = os.getenv("UNIO_COLLECTOR_CLAMAV_DATABASE", "")
    database_args = ("--database", database) if database else ()
    return (clamscan, *database_args, "--infected", "--recursive", "--no-summary")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
