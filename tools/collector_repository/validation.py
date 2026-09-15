"""Build and validate a standalone repository without private checkout imports."""

from __future__ import annotations

import os
import tempfile
import tomllib
import venv
from pathlib import Path

from tools.collector_repository.artifacts import PublicAssistantArtifactPolicy
from tools.collector_repository.comments import PublicCommentPolicy
from tools.collector_repository.identity import RepositoryIdentity, canonical_json
from tools.collector_repository.naming import PublicNamingValidator
from tools.collector_repository.paths import external_output, require
from tools.collector_repository.process import RepositoryProcess
from tools.collector_repository.secrets import GitleaksSecretScanner


class RepositoryValidator:
    """Coordinate the bounded public checks and existing collector build tools."""

    def validate(self, root: Path, output: Path, *, native: bool = False) -> dict[str, object]:
        """Validate source or a pristine export, recording honest partial failures."""
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
        payload: dict[str, object] = {"schema_version": "2026-09-collector-validation-v1", "status": "failed", "pristine_export": before is not None}
        payload["project_disclosure"] = "verified-publication-attestation" if before is not None and "sensitive_data_validation" in before else "not-attested"
        with tempfile.TemporaryDirectory(prefix="unio-collector-standalone-validation-", dir=output.parent) as raw:
            workspace = Path(raw)
            external_output(root, workspace)
            process = RepositoryProcess(workspace, output)
            try:
                payload["secret_scan"] = GitleaksSecretScanner().scan(root, output)
                python = self._environment(root, workspace, process)
                self._source(root, workspace, python, process)
                wheel = self._wheel(root, output, python, process)
                if native:
                    self._native(root, output, python, wheel, process)
                if before is not None:
                    require(RepositoryIdentity().verify(root) == before, "Validation changed the pristine export.")
                payload["status"] = "passed"
                payload["wheel"] = wheel.name
            finally:
                payload["steps"] = process.steps
                (output / "validation-summary.json").write_bytes(canonical_json(payload))
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

    def _source(self, root: Path, workspace: Path, python: Path, process: RepositoryProcess) -> None:
        executable = str(python)
        for name, arguments in (
            ("compile", ["-m", "compileall", "-q", "unio_collector", "tools", "tests/standalone"]),
            ("ruff", ["-m", "ruff", "check", "--no-cache", "unio_collector", "tools", "tests/standalone"]),
            ("format", ["-m", "ruff", "format", "--check", "--no-cache", "unio_collector", "tools", "tests/standalone"]),
            ("pyright", ["-m", "pyright", "--pythonpath", executable]),
            ("tests", ["-m", "pytest", "-q", "-p", "no:cacheprovider", "--basetemp", str(workspace / "pytest"), "tests/standalone"]),
        ):
            process.run(name, [executable, *arguments], cwd=root)

    def _wheel(self, root: Path, output: Path, python: Path, process: RepositoryProcess) -> Path:
        wheel_dir = output / "wheel"
        process.run(
            "wheel-build", [str(python), "-B", "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "--wheel-dir", str(wheel_dir), str(root)], cwd=output
        )
        wheels = list(wheel_dir.glob("*.whl"))
        require(len(wheels) == 1, "Expected exactly one standalone wheel.")
        wheel = wheels[0]
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
        )
        return wheel

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
