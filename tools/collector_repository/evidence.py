"""Fail-closed, same-run source-validation transfer to native packaging."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from tools.collector_repository.identity import RepositoryIdentity, canonical_json, read_json, sha256
from tools.collector_repository.partition import TestPartition
from tools.collector_repository.paths import external_output, regular_file, require

SOURCE_STEPS = (
    "dependencies",
    "dependency-check",
    "dependency-inventory",
    "compile",
    "ruff",
    "format",
    "pyright",
    "tests",
    "wheel-build",
    "dependency-inventory-final",
)
SCHEMA = "unio-native-source-transfer-v1"


class SourceValidationEvidence:
    """Accept only a complete, byte-bound source job from this workflow attempt."""

    def checkout_sha(self, root: Path, expected: str | None) -> str:
        """Bind evidence to the actual checkout, never a supplied label alone."""
        executable = shutil.which("git") or ""
        require(bool(executable), "Git is required for source evidence.")
        result = subprocess.run([executable, "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=False, timeout=30)  # noqa: S603
        require(result.returncode == 0, "Source evidence requires a Git checkout.")
        actual = result.stdout.strip()
        require(re.fullmatch(r"[0-9a-f]{40}", actual) is not None, "Invalid checkout SHA.")
        require(expected is None or actual == expected, "Source evidence checkout SHA mismatch.")
        return actual

    def context(self, root: Path, source_sha: str | None, inventory: Path, workers: int, test_shards: int = 1) -> dict[str, Any]:
        """Cover every export byte, resolved dependency and runner configuration."""
        identity = RepositoryIdentity().verify(root)
        require("sensitive_data_validation" in identity, "Source transfer requires publication disclosure attestation.")
        dependencies = json.loads(inventory.read_bytes())
        require(isinstance(dependencies, list) and bool(dependencies), "Missing dependency inventory.")
        require(
            all(isinstance(row, dict) and set(row) == {"name", "version"} and all(isinstance(v, str) and v for v in row.values()) for row in dependencies),
            "Malformed dependency inventory.",
        )
        dependencies = sorted(dependencies, key=lambda row: row["name"].casefold())
        require(len({row["name"].casefold() for row in dependencies}) == len(dependencies), "Duplicate dependencies.")
        machine = platform.machine().lower()
        architecture = {"amd64": "x86_64", "aarch64": "arm64"}.get(machine, machine)
        target = f"{platform.system().lower()}-{architecture}"
        target = target.replace("darwin-", "macos-")
        require(target in {"windows-x86_64", "linux-x86_64", "macos-x86_64", "macos-arm64"}, "Unsupported source evidence target.")
        require(os.environ.get("UNIO_NATIVE_TARGET", target) == target, "Runner target mismatch.")
        return {
            "checkout_sha": self.checkout_sha(root, source_sha),
            "export_provenance": identity,
            "target": target,
            "python": {"implementation": platform.python_implementation(), "version": platform.python_version(), "abi": sys.implementation.cache_tag},
            "dependencies": dependencies,
            "pytest_workers": workers,
            "test_shards": test_shards,
            "workflow": {
                key: os.environ.get(key) for key in ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_EVENT_NAME", "ImageOS", "ImageVersion")
            },
        }

    def write(self, root: Path, output: Path, source_sha: str | None, workers: int, test_shards: int = 1) -> None:
        """Seal source checks and wheel bytes; the consumer owns fresh clean-wheel checks."""
        context = self.context(root, source_sha, output / "dependency-inventory.log", workers, test_shards)
        final_inventory = json.loads((output / "dependency-inventory-final.log").read_bytes())
        require(sorted(final_inventory, key=lambda row: row["name"].casefold()) == context["dependencies"], "Source dependencies changed during validation.")
        summary = read_json(output / "validation-summary.json")
        self._summary(summary, workers)
        require(summary.get("test_partition", {}).get("count", 1) == test_shards, "Source shard configuration mismatch.")
        wheel = regular_file(output, f"wheel/{summary['wheel']}")
        files = {name: sha256(regular_file(output, name).read_bytes()) for name in ("validation-summary.json", f"wheel/{wheel.name}")}
        (output / "source-evidence.json").write_bytes(canonical_json({"schema_version": SCHEMA, "context": context, "files": files}))

    def accept(self, root: Path, evidence: Path, output: Path, context: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
        """Reject absent, cross-run, cross-target, modified or incomplete evidence."""
        evidence = external_output(root, evidence)
        require(evidence != output and not evidence.is_relative_to(output) and not output.is_relative_to(evidence), "Evidence and output must be disjoint.")
        if context["test_shards"] > 1:
            return self._accept_shards(evidence, output, context)
        return self._accept_single(evidence, output, context)

    def _accept_single(self, evidence: Path, output: Path, context: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
        """Check one sealed member; only the aggregate method admits sharded coverage."""
        proof = read_json(regular_file(evidence, "source-evidence.json"))
        require(set(proof) == {"schema_version", "context", "files"} and proof["schema_version"] == SCHEMA, "Unsupported source evidence.")
        require(proof["context"] == context, "Source evidence identity, target, dependencies or configuration mismatch.")
        summary = read_json(regular_file(evidence, "validation-summary.json"))
        self._summary(summary, context["pytest_workers"])
        require(summary.get("test_partition", {}).get("count", 1) == context["test_shards"], "Source shard configuration mismatch.")
        wheel_name = summary["wheel"]
        require(isinstance(wheel_name, str) and Path(wheel_name).name == wheel_name and wheel_name.endswith(".whl"), "Invalid transferred wheel name.")
        names = {"validation-summary.json", f"wheel/{wheel_name}"}
        require(isinstance(proof["files"], dict) and set(proof["files"]) == names, "Incomplete source evidence files.")
        actual = {path.relative_to(evidence).as_posix() for path in evidence.rglob("*") if path.is_file()}
        require(actual == names | {"source-evidence.json"}, "Unexpected source transfer files.")
        for name, digest in proof["files"].items():
            require(sha256(regular_file(evidence, name).read_bytes()) == digest, "Source evidence file hash mismatch.")
        shutil.copyfile(evidence / "source-evidence.json", output / "source-evidence.json")
        return regular_file(evidence, f"wheel/{wheel_name}"), {
            "status": "verified",
            "context": context,
            "files": proof["files"],
            "steps": summary["steps"],
            **({"test_partition": summary["test_partition"]} if "test_partition" in summary else {}),
        }

    def _accept_shards(self, evidence: Path, output: Path, context: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
        """Verify every same-attempt source shard before admitting a packaging wheel."""
        directories = sorted(evidence.iterdir())
        require(
            len(directories) == context["test_shards"] and all(path.is_dir() and not path.is_symlink() for path in directories),
            "Missing or unexpected source shards.",
        )
        accepted = []
        wheels = []
        for number, directory in enumerate(directories):
            destination = output / f"source-shard-{number}"
            destination.mkdir()
            wheel, result = self._accept_single(directory, destination, context)
            accepted.append(result)
            wheels.append(wheel)
        TestPartition.complete([result["test_partition"] for result in accepted], context["test_shards"])
        result = {"status": "verified", "context": context, "shards": accepted}
        (output / "source-evidence.json").write_bytes(canonical_json(result))
        return wheels[0], result

    @staticmethod
    def _summary(summary: dict[str, Any], workers: int) -> None:
        require(
            summary.get("status") == "passed" and summary.get("pristine_export") is True and summary.get("validation_scope") == "source-for-native",
            "Source validation did not pass on a pristine export.",
        )
        require(
            type(summary.get("pytest_workers")) is int
            and summary.get("pytest_workers") == workers
            and summary.get("project_disclosure") == "verified-publication-attestation",
            "Source validation configuration mismatch.",
        )
        if "test_partition" in summary:
            TestPartition.validate(summary["test_partition"])
        scan = summary.get("secret_scan")
        require(isinstance(scan, dict) and scan.get("status") == "clean" and scan.get("findings") == [], "Source secret scan missing or failed.")
        wheel = summary.get("wheel")
        require(isinstance(wheel, str) and Path(wheel).name == wheel and wheel.endswith(".whl"), "Invalid source wheel name.")
        steps = summary.get("steps", [])
        require(isinstance(steps, list) and all(isinstance(step, dict) for step in steps), "Malformed source steps.")
        require([step.get("name") for step in steps] == list(SOURCE_STEPS), "Mandatory source stages missing or reordered.")
        require(
            all(step.get("status") == "passed" and type(step.get("exit_code")) is int and step.get("exit_code") == 0 for step in steps),
            "Incomplete source stage.",
        )
