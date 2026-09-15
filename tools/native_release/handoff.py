"""Create and validate exact unsigned native validation handoffs."""

# ruff: noqa: EM101, EM102, TRY003

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

PROVENANCE_NAME = "unsigned-artifact-provenance.json"
SHA256_HEX_LENGTH = 64


@dataclass(frozen=True)
class UnsignedHandoff:
    """Identity expected for one unsigned native artifact set."""

    source_sha: str
    target: str
    version: str
    workflow_run_id: str

    def create(self, root: Path) -> dict[str, object]:
        """Validate unsigned evidence and write its byte-exact provenance."""
        identity = self._validate_identity(root)
        payload = {
            **identity,
            "artifact_hashes": _artifact_hashes(root),
            "schema_version": "2026-08-native-unsigned-handoff-v1",
            "signing_status": "unsigned",
            "workflow_run_id": self.workflow_run_id,
        }
        _write_json(root / PROVENANCE_NAME, payload)
        return payload

    def validate(self, root: Path) -> dict[str, object]:
        """Fail closed unless the downloaded handoff is exact and untampered."""
        path = root / PROVENANCE_NAME
        if not path.is_file():
            raise ValueError(f"Unsigned native handoff provenance is missing: {path}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != "2026-08-native-unsigned-handoff-v1":
            raise ValueError("Unsigned native handoff schema is unsupported.")
        if payload.get("signing_status") != "unsigned":
            raise ValueError("Unsigned native handoff has an invalid signing status.")
        if payload.get("workflow_run_id") != self.workflow_run_id:
            raise ValueError("Unsigned native handoff workflow run does not match.")
        identity = self._validate_identity(root)
        if any(payload.get(key) != value for key, value in identity.items()):
            raise ValueError("Unsigned native handoff identity does not match.")
        hashes = payload.get("artifact_hashes")
        if not isinstance(hashes, dict) or hashes != _artifact_hashes(root):
            raise ValueError("Unsigned native handoff files or hashes do not match.")
        return payload

    def _validate_identity(self, root: Path) -> dict[str, object]:
        manifest = _read_json(root / "native-release-manifest.json")
        lock = _read_json(root / "native-hash-lock-evidence.json")
        build = _read_json(root / "native-build-summary.json")
        operating_system, architecture = self.target.split("-", maxsplit=1)
        expected = {
            "architecture": architecture,
            "collector_wheel_sha256": manifest.get("collector_wheel_sha256"),
            "lock_filename": f"native-{self.target}.lock",
            "lock_sha256": lock.get("lock_sha256"),
            "operating_system": operating_system,
            "source_sha": self.source_sha,
            "target": self.target,
            "version": self.version,
        }
        if manifest.get("source_commit") != self.source_sha or manifest.get("version") != self.version:
            raise ValueError("Unsigned native release manifest source or version does not match.")
        if manifest.get("operating_system") != operating_system or manifest.get("architecture") != architecture:
            raise ValueError("Unsigned native release manifest target does not match.")
        if lock.get("target") != self.target or lock.get("lock_filename") != expected["lock_filename"]:
            raise ValueError("Unsigned native lock evidence target does not match.")
        if not isinstance(lock.get("lock_sha256"), str) or len(str(lock["lock_sha256"])) != SHA256_HEX_LENGTH:
            raise ValueError("Unsigned native lock evidence has no valid lock hash.")
        wheel_hash = manifest.get("collector_wheel_sha256")
        if (
            not isinstance(wheel_hash, str)
            or len(wheel_hash) != SHA256_HEX_LENGTH
            or build.get("collector_wheel_sha256") != wheel_hash
            or lock.get("collector_wheel_sha256") != wheel_hash
        ):
            raise ValueError("Unsigned native collector wheel identity does not match.")
        return expected


def main() -> int:
    """Create or validate one native unsigned handoff."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("create", "validate"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    args = parser.parse_args()
    handoff = UnsignedHandoff(
        source_sha=args.source_sha,
        target=args.target,
        version=args.version,
        workflow_run_id=args.workflow_run_id,
    )
    if args.command == "create":
        handoff.create(args.root.resolve())
    else:
        handoff.validate(args.root.resolve())
    return 0


def _artifact_hashes(root: Path) -> dict[str, str]:
    return {path.relative_to(root).as_posix(): _sha256(path) for path in sorted(root.rglob("*")) if path.is_file() and path.name != PROVENANCE_NAME}


def _read_json(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise ValueError(f"Unsigned native handoff evidence is missing: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Unsigned native handoff evidence is invalid: {path}")
    return payload


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
