"""Seal existing packages and their complete supporting evidence, without a build."""

from __future__ import annotations

import hashlib
import shutil
from typing import TYPE_CHECKING, Any

from tools.collector_repository.identity import canonical_json, read_json
from tools.collector_repository.paths import external_output, regular_file, require
from tools.test_packages.context import TARGETS
from tools.test_packages.evidence import NativeEvidence

if TYPE_CHECKING:
    from pathlib import Path

REQUIRED_SHARDS = 2

PROOFS = ("validation-summary.json", "process-progress.json", "source-evidence.json", "installed-wheel-summary.json")
NATIVE_PROOFS = (
    "native-build-summary.json",
    "native-release-manifest.json",
    "native-installer-summary.json",
    "native-malware-scan-summary.json",
    "native-hash-lock-evidence.json",
)


class TestPackagePacket:
    """Retain only exact successful artifacts and structured acceptance proofs."""

    def inventory(self, root: Path, target: str) -> set[str]:
        """Compute admissible membership from the finite evidence contract."""
        manifest = read_json(root / "native/native-release-manifest.json")
        names = set(PROOFS) | {"native/" + name for name in NATIVE_PROOFS} | {"native/" + name for name in manifest["artifact_hashes"]}
        if target == "windows-x86_64":
            names.add("native/native-msi-metadata.json")
        for number in range(2):
            prefix = f"source/{number}/"
            proof = read_json(root / prefix / "source-evidence.json")
            names.add(prefix + "source-evidence.json")
            names.update(prefix + name for name in proof["files"])
        return names

    def seal(self, trusted: Path, validation: Path, sources: Path, request: dict[str, Any], target: str, job_id: int, output: Path) -> dict[str, Any]:
        """Copy exact bytes only; never rebuild or repackage an installer."""
        output = external_output(trusted, output, empty=True)
        validation = external_output(trusted, validation)
        sources = external_output(trusted, sources)
        require(
            not output.is_relative_to(validation)
            and not validation.is_relative_to(output)
            and not output.is_relative_to(sources)
            and not sources.is_relative_to(output),
            "Packet and inputs must be disjoint.",
        )
        require(target in TARGETS and type(job_id) is int and not output.exists(), "Invalid packet output/job.")
        output.mkdir(parents=True)
        directories = sorted(sources.iterdir())
        require(len(directories) == REQUIRED_SHARDS and all(p.is_dir() and not p.is_symlink() for p in directories), "Incomplete source transfer.")
        for number, directory in enumerate(directories):
            proof = read_json(regular_file(directory, "source-evidence.json"))
            for name in {"source-evidence.json", *proof["files"]}:
                self._copy(regular_file(directory, name), output / "source" / str(number) / name)
        manifest = read_json(regular_file(validation, "native/native-release-manifest.json"))
        names = set(PROOFS) | {"native/" + n for n in NATIVE_PROOFS} | {"native/" + n for n in manifest["artifact_hashes"]}
        if target == "windows-x86_64":
            names.add("native/native-msi-metadata.json")
        for name in names:
            self._copy(regular_file(validation, name), output / name)
        NativeEvidence(trusted).verify(output, request["context"], target)
        inventory = {name: hashlib.sha256(regular_file(output, name).read_bytes()).hexdigest() for name in sorted(self.inventory(output, target))}
        payload = {"schema_version": 1, "purpose": "unsigned-manual-test-only", "request": request, "target": target, "job_id": job_id, "files": inventory}
        (output / "packet.json").write_bytes(canonical_json(payload))
        return payload

    def verify(self, root: Path, packet: dict[str, Any], request: dict[str, Any]) -> None:
        """Reject extra/missing members as well as changed byte identities."""
        require(
            set(packet) == {"schema_version", "purpose", "request", "target", "job_id", "files"}
            and packet["schema_version"] == 1
            and packet["purpose"] == "unsigned-manual-test-only"
            and packet["request"] == request,
            "Packet identity mismatch.",
        )
        require(set(packet["files"]) == self.inventory(root, packet["target"]), "Unexpected packet membership.")
        for name, expected in packet["files"].items():
            require(hashlib.sha256(regular_file(root, name).read_bytes()).hexdigest() == expected, "Packet content changed.")

    @staticmethod
    def _copy(source: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
