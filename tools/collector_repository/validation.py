"""Build and validate a standalone repository without private checkout imports."""

from __future__ import annotations

import os
import tempfile
import tomllib
import venv
from contextlib import suppress
from pathlib import Path

from tools.collector_repository.artifacts import PublicAssistantArtifactPolicy
from tools.collector_repository.comments import PublicCommentPolicy
from tools.collector_repository.durations import PytestDurationDiagnostics
from tools.collector_repository.evidence import SourceValidationEvidence
from tools.collector_repository.identity import RepositoryIdentity, canonical_json, read_json
from tools.collector_repository.naming import PublicNamingValidator
from tools.collector_repository.partition import MAX_TEST_SHARDS
from tools.collector_repository.paths import external_output, require
from tools.collector_repository.process import RepositoryProcess
from tools.collector_repository.secrets import GitleaksSecretScanner


class RepositoryValidator:
    """Coordinate the bounded public checks and existing collector build tools."""

    def validate(
        self,
        root: Path,
        output: Path,
        *,
        native: bool = False,
        source_sha: str | None = None,
        pytest_workers: int = 1,
        emit_source_evidence: bool = False,
        source_evidence: Path | None = None,
        test_shard: int = 0,
        test_shards: int = 1,
    ) -> dict[str, object]:
        """Validate source or a pristine export, recording honest partial failures."""
        require(not emit_source_evidence or (not native and source_evidence is None), "Invalid source-transfer mode.")
        require(source_evidence is None or native, "Source evidence requires native packaging.")
        require(
            type(test_shards) is int and 1 <= test_shards <= MAX_TEST_SHARDS and type(test_shard) is int and 0 <= test_shard < test_shards,
            "Invalid test partition configuration.",
        )
        require(test_shards == 1 or emit_source_evidence or source_evidence is not None, "Test shards require source transfer.")
        require(pytest_workers >= 1, "Pytest worker count must be a positive integer.")
        root = root.resolve()
        PublicAssistantArtifactPolicy().validate(root)
        PublicNamingValidator().validate(root)
        PublicCommentPolicy().validate(root)
        output = external_output(root, output, empty=True)
        output.mkdir(parents=True, exist_ok=True)
        pristine = (root / "export-manifest.json").exists()
        before: dict[str, object] | None = None
        if pristine:
            try:
                before = RepositoryIdentity().verify(root)
            except ValueError:
                before = None
        payload: dict[str, object] = {
            "schema_version": "2026-09-collector-validation-v1",
            "status": "failed",
            "pristine_export": before is not None,
            "pytest_workers": pytest_workers,
            "validation_scope": "source-for-native" if emit_source_evidence else "native-packaging" if source_evidence is not None else "complete",
        }
        payload["project_disclosure"] = "verified-publication-attestation" if before is not None and "sensitive_data_validation" in before else "not-attested"
        with tempfile.TemporaryDirectory(prefix="unio-collector-standalone-validation-", dir=output.parent) as raw:
            workspace = Path(raw)
            external_output(root, workspace)
            process = RepositoryProcess(workspace, output)
            try:
                payload["secret_scan"] = GitleaksSecretScanner().scan(root, output)
                python = self._environment(root, workspace, process)
                if emit_source_evidence or source_evidence is not None:
                    require(before is not None, "Native job transfer requires a pristine export.")
                    source_sha = SourceValidationEvidence().checkout_sha(root, source_sha)
                    process.run("dependency-inventory", [str(python), "-I", "-m", "pip", "list", "--format=json"], cwd=workspace)
                if source_evidence is None:
                    self._source(root, workspace, python, process, pytest_workers=pytest_workers, test_shard=test_shard, test_shards=test_shards)
                    if test_shards > 1:
                        payload["test_partition"] = read_json(workspace / "partitions/partition.json")
                    wheel = (
                        self._build_wheel(root, output, python, process)
                        if emit_source_evidence
                        else self._wheel(root, output, python, process, source_sha=source_sha)
                    )
                else:
                    transfer = SourceValidationEvidence()
                    context = transfer.context(root, source_sha, output / "dependency-inventory.log", pytest_workers, test_shards)
                    with suppress(OSError):
                        (output / "source-context.json").write_bytes(canonical_json(context))
                    wheel, payload["source_validation"] = transfer.accept(root, source_evidence, output, context)
                    self._validate_wheel(root, output, python, wheel, process, source_sha=source_sha)
                if native:
                    self._native(root, output, python, wheel, process)
                if emit_source_evidence:
                    process.run("dependency-inventory-final", [str(python), "-I", "-m", "pip", "list", "--format=json"], cwd=workspace)
                if before is not None:
                    require(RepositoryIdentity().verify(root) == before, "Validation changed the pristine export.")
                payload["status"] = "passed"
                payload["wheel"] = wheel.name
            finally:
                with suppress(Exception):
                    PytestDurationDiagnostics().retain(
                        output,
                        source_sha=source_sha,
                        export=before,
                        workers=pytest_workers,
                        shard=test_shard,
                        shards=test_shards,
                        enabled=source_evidence is None,
                    )
                payload["steps"] = process.steps
                (output / "validation-summary.json").write_bytes(canonical_json(payload))
        if emit_source_evidence:
            SourceValidationEvidence().write(root, output, source_sha, pytest_workers, test_shards)
        return payload

    def _environment(self, root: Path, workspace: Path, process: RepositoryProcess) -> Path:
        project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        require(project["name"] == "unio-collector", "Validation requires the standalone collector project.")
        require(project["scripts"] == {"unio-collector": "unio_collector.collector_cli.app:main"}, "Unexpected standalone console scripts.")
        environment = workspace / "environment"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        dependencies = [*project["dependencies"], *project["optional-dependencies"]["dev"]]
        process.run(
            "dependencies", [str(python), "-I", "-m", "pip", "install", "-c", str(root / "requirements/dev-constraints.txt"), *dependencies], cwd=workspace
        )
        process.run("dependency-check", [str(python), "-I", "-m", "pip", "check"], cwd=workspace)
        return python

    def _source(
        self, root: Path, workspace: Path, python: Path, process: RepositoryProcess, *, pytest_workers: int = 1, test_shard: int = 0, test_shards: int = 1
    ) -> None:
        executable = str(python)
        tests = ["-m", "pytest", "-q", "-p", "no:cacheprovider", "--durations=20", "--basetemp", str(workspace / "pytest")]
        if pytest_workers > 1:
            tests.extend(["-n", str(pytest_workers), "--dist", "loadscope"])
        if test_shards > 1:
            tests.extend(["-p", "tools.collector_repository.pytest_partition"])
        tests.append("tests/standalone")
        for name, arguments in (
            ("compile", ["-m", "compileall", "-q", "unio_collector", "tools", "tests/standalone"]),
            ("ruff", ["-m", "ruff", "check", "--no-cache", "--output-format", "concise", "unio_collector", "tools", "tests/standalone"]),
            ("format", ["-m", "ruff", "format", "--check", "--no-cache", "unio_collector", "tools", "tests/standalone"]),
            ("pyright", ["-m", "pyright", "--pythonpath", executable]),
            ("tests", tests),
        ):
            if name == "tests" and test_shards > 1:
                previous = {key: os.environ.get(key) for key in ("UNIO_TEST_SHARD_INDEX", "UNIO_TEST_SHARD_COUNT", "UNIO_TEST_SHARD_OUTPUT")}
                try:
                    os.environ.update(
                        {
                            "UNIO_TEST_SHARD_INDEX": str(test_shard),
                            "UNIO_TEST_SHARD_COUNT": str(test_shards),
                            "UNIO_TEST_SHARD_OUTPUT": str(workspace / "partitions"),
                        }
                    )
                    process.run(name, [executable, *arguments], cwd=root)
                finally:
                    for key, value in previous.items():
                        if value is None:
                            os.environ.pop(key, None)
                        else:
                            os.environ[key] = value
            else:
                process.run(name, [executable, *arguments], cwd=root)

    def _wheel(
        self,
        root: Path,
        output: Path,
        python: Path,
        process: RepositoryProcess,
        *,
        source_sha: str | None = None,
    ) -> Path:
        wheel = self._build_wheel(root, output, python, process)
        self._validate_wheel(root, output, python, wheel, process, source_sha=source_sha)
        return wheel

    def _build_wheel(self, root: Path, output: Path, python: Path, process: RepositoryProcess) -> Path:
        wheel_dir = output / "wheel"
        process.run(
            "wheel-build", [str(python), "-B", "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "--wheel-dir", str(wheel_dir), str(root)], cwd=output
        )
        wheels = list(wheel_dir.glob("*.whl"))
        require(len(wheels) == 1, "Expected exactly one standalone wheel.")
        return wheels[0]

    def _validate_wheel(self, root: Path, output: Path, python: Path, wheel: Path, process: RepositoryProcess, *, source_sha: str | None = None) -> None:
        process.run(
            "installed-wheel",
            [
                str(python),
                "-B",
                "-m",
                "tools.validate_collector_wheel",
                "--wheel",
                str(wheel),
                "--fixture",
                "tests/standalone/fixtures/cost.json",
                "--cli-snapshot",
                "tests/collector/snapshots/collector_cli_contract.json",
                "--summary-output",
                str(output / "installed-wheel-summary.json"),
            ],
            cwd=root,
            source_sha=source_sha,
        )

    def _native(self, root: Path, output: Path, python: Path, wheel: Path, process: RepositoryProcess) -> None:
        native = output / "native"
        commands = (
            ("native-build", "tools.build_native_collector", ["--wheel", str(wheel), "--output", str(native), "--require-hash-lock"]),
            ("native-installer", "tools.package_native_collector", ["--payload", str(native / "payload"), "--output", str(native), "--require-installer"]),
            (
                "native-malware",
                "tools.scan_native_collector",
                ["--target", str(native), "--summary-output", str(native / "native-malware-scan-summary.json"), "--require-scanner"],
            ),
        )
        for name, module, arguments in commands:
            process.run(name, [str(python), "-B", "-m", module, *arguments], cwd=root)
