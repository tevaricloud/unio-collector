"""Traditional public Python, dependency and workflow security checks."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import tomllib
import venv
from pathlib import Path

from tools.collector_repository.artifacts import PublicAssistantArtifactPolicy
from tools.collector_repository.comments import PublicCommentPolicy
from tools.collector_repository.identity import canonical_json, sha256
from tools.collector_repository.naming import PublicNamingValidator
from tools.collector_repository.paths import external_output, regular_file, relative_path, require
from tools.collector_repository.process import RepositoryProcess
from tools.collector_repository.secrets import GitleaksSecretScanner
from tools.collector_repository.toolchain import CiToolchain


class RepositorySecurityValidator:
    """Keep security ownership separate from the Python and native build gates."""

    def validate(self, root: Path, output: Path) -> dict[str, object]:
        """Run all required security checks with safe, separate evidence."""
        root = root.resolve()
        PublicAssistantArtifactPolicy().validate(root)
        PublicNamingValidator().validate(root)
        PublicCommentPolicy().validate(root)
        output = external_output(root, output, empty=True)
        output.mkdir(parents=True, exist_ok=True)
        config = CiToolchain().configuration(root)
        summary: dict[str, object] = {"status": "failed", "tools": config["python"]}
        with tempfile.TemporaryDirectory(prefix="Unio-security-validation-", dir=output.parent) as raw:
            workspace = Path(raw)
            process = RepositoryProcess(workspace, output)
            try:
                summary["secret_scan"] = GitleaksSecretScanner().scan(root, output)
                environment = workspace / "environment"
                venv.EnvBuilder(with_pip=True).create(environment)
                python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
                packages = [f"{name}=={version}" for name, version in config["python"].items()]
                process.run(
                    "security-tools",
                    [str(python), "-I", "-m", "pip", "install", "-c", str(root / "requirements/dev-constraints.txt"), *packages],
                    cwd=workspace,
                )
                check = "import importlib.metadata as m; assert " + repr(config["python"]) + " == {k:m.version(k) for k in " + repr(config["python"]) + "}"
                self._run([str(python), "-I", "-c", check], root, process, {0})
                summary["bandit"] = self._bandit(root, workspace, python, process, config["bandit"])
                summary["dependencies"] = self._audit(root, workspace, python, process, packages)
                executable = Path(os.environ.get("UNIO_COLLECTOR_ACTIONLINT", "actionlint"))
                CiToolchain().verify_binary(executable, "actionlint", config["binaries"]["actionlint"]["version"])
                workflows = sorted(path for path in (root / ".github/workflows").rglob("*") if path.is_file() and path.suffix in {".yml", ".yaml"})
                require(bool(workflows), "No public workflows to scan.")
                self._run([str(executable), "-shellcheck=", "-pyflakes=", *map(str, workflows)], root, process, {0})
                summary["actionlint"] = {"status": "clean", "workflows": [path.name for path in workflows]}
                zizmor = environment / ("Scripts/zizmor.exe" if os.name == "nt" else "bin/zizmor")
                result = self._run(
                    [
                        str(zizmor),
                        "--offline",
                        "--strict-collection",
                        "--no-config",
                        "--no-ignores",
                        "--no-progress",
                        "--min-severity",
                        "medium",
                        "--min-confidence",
                        "medium",
                        "--format",
                        "json",
                        *map(str, workflows),
                    ],
                    root,
                    process,
                    {0},
                )
                require(json.loads(result.stdout) == [], "Zizmor report contains an unexpected finding.")
                summary["zizmor"] = {"status": "clean", "workflows": [path.name for path in workflows], "mode": "offline"}
                summary["status"] = "passed"
            finally:
                (output / "security-summary.json").write_bytes(canonical_json(summary))
        return summary

    def _run(self, command: list[str], root: Path, process: RepositoryProcess, codes: set[int]) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(command, cwd=root, env=process.environment(), capture_output=True, text=True, timeout=600, check=False)  # noqa: S603
        except (OSError, subprocess.SubprocessError, UnicodeError):
            message = "Required public security scanner could not complete."
            raise ValueError(message) from None
        require(result.returncode in codes, "Required public security scanner failed.")
        return result

    def _bandit(self, root: Path, workspace: Path, python: Path, process: RepositoryProcess, policy: dict[str, object]) -> dict[str, object]:
        require(policy["minimum_severity"] == policy["minimum_confidence"] == "medium", "Unexpected Bandit policy.")
        report = workspace / "bandit.json"
        result = self._run(
            [str(python), "-I", "-m", "bandit", "-r", str(root), "--ignore-nosec", "-ll", "-ii", "-f", "json", "-o", str(report)], root, process, {0, 1}
        )
        data = json.loads(report.read_bytes())
        require(isinstance(data, dict) and data.get("errors") == [] and isinstance(data.get("results"), list), "Bandit report is incomplete.")
        exceptions = policy["exceptions"]
        if not isinstance(exceptions, list):
            message = "Invalid Bandit approvals."
            raise ValueError(message)
        seen: set[int] = set()
        findings = []
        for item in data["results"]:
            name = Path(item["filename"]).relative_to(root).as_posix()
            relative_path(name)
            identity = {"path": name, "rule": item["test_id"], "line": item["line_number"], "source_sha256": sha256(regular_file(root, name).read_bytes())}
            matches = [
                index
                for index, approval in enumerate(exceptions)
                if all(approval.get(key) == value for key, value in identity.items()) and approval.get("rationale")
            ]
            require(len(matches) <= 1, "Duplicate Bandit approvals.")
            seen.update(matches)
            findings.append({**identity, "approved": bool(matches)})
        require((result.returncode == 1) == bool(findings), "Bandit result/report disagreement.")
        require(seen == set(range(len(exceptions))), "Stale Bandit approval.")
        require(all(item["approved"] for item in findings), "Bandit reported an unapproved security finding.")
        return {"status": "clean", "minimum_severity": "medium", "minimum_confidence": "medium", "reviewed_findings": findings}

    def _audit(self, root: Path, workspace: Path, python: Path, process: RepositoryProcess, packages: list[str]) -> list[dict[str, object]]:
        project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        summaries = []
        for kind, dependencies in (("runtime", project["dependencies"]), ("development-security", [*project["optional-dependencies"]["dev"], *packages])):
            target = workspace / f"audit-{kind}"
            venv.EnvBuilder(with_pip=False).create(target)
            target_python = target / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            process.run(
                f"audit-install-{kind}",
                [
                    str(python),
                    "-I",
                    "-m",
                    "pip",
                    "--python",
                    str(target_python),
                    "install",
                    "-c",
                    str(root / "requirements/dev-constraints.txt"),
                    *dependencies,
                ],
                cwd=workspace,
            )
            site = self._run([str(target_python), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"], root, process, {0}).stdout.strip()
            report = workspace / f"{kind}-audit.json"
            result = self._run(
                [
                    str(python),
                    "-I",
                    "-m",
                    "pip_audit",
                    "--path",
                    site,
                    "--strict",
                    "--progress-spinner",
                    "off",
                    "--format",
                    "json",
                    "--output",
                    str(report),
                ],
                root,
                process,
                {0, 1},
            )
            data = json.loads(report.read_bytes())
            require(isinstance(data.get("dependencies"), list), "Dependency audit report is incomplete.")
            vulnerabilities = [
                {"package": item["name"], "version": item["version"], "ids": [vuln["id"] for vuln in item.get("vulns", [])]}
                for item in data["dependencies"]
                if item.get("vulns")
            ]
            (process.output / f"{kind}-audit-summary.json").write_bytes(canonical_json({"contract": kind, "vulnerabilities": vulnerabilities}))
            require(result.returncode == 0 and not vulnerabilities, "Dependency audit reported an unapproved vulnerability.")
            require(
                isinstance(data.get("dependencies"), list) and all("vulns" in item and not item["vulns"] for item in data["dependencies"]),
                "Dependency audit report is incomplete or vulnerable.",
            )
            summaries.append(
                {"contract": kind, "status": "clean", "packages": [{"name": item["name"], "version": item["version"]} for item in data["dependencies"]]}
            )
        return summaries
