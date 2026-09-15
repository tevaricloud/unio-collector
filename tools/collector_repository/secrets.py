"""Pinned, offline and secret-safe public source-tree scanning."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from tools.collector_repository.identity import canonical_json, sha256
from tools.collector_repository.paths import external_output, regular_file, relative_path, repository_files, require

GITLEAKS_VERSION = "8.30.1"
CONFIG_SHA256 = "0adb45e969ad1c82f59da84cd8bdd3114e419d82cca867dfe7bc79d194570180"


class GitleaksSecretScanner:
    """Require the pinned executable and exact rules; never retain raw output."""

    def scan(self, root: Path, output: Path | None = None) -> dict[str, object]:
        """Scan all generated payload files, including identities and fixtures."""
        root = root.resolve()
        names = repository_files(root)
        require(not any(Path(name).name.casefold() == ".gitleaksignore" for name in names), "Gitleaks suppression files are prohibited.")
        config_root = Path(__file__).resolve().parents[2]
        config = config_root / "requirements/secret-scanning.toml"
        if not config.exists():
            config = config_root / "tools/collector_export/assets/secret-scanning.toml"
        require(config.is_file() and sha256(config.read_bytes()) == CONFIG_SHA256, "Gitleaks configuration integrity failed.")
        executable = os.environ.get("UNIO_COLLECTOR_GITLEAKS") or shutil.which("gitleaks")
        require(bool(executable), f"Gitleaks {GITLEAKS_VERSION} executable is required.")
        environment = {key: value for key, value in os.environ.items() if not key.startswith("GITLEAKS_")}
        before = {name: sha256(regular_file(root, name).read_bytes()) for name in names}
        if output is not None:
            external_output(root, output)
            output.mkdir(parents=True, exist_ok=True)
        parent = output if output is not None else root.parent
        with tempfile.TemporaryDirectory(prefix="Unio-collector-secret-scan-", dir=parent) as raw:
            workspace = Path(raw)
            external_output(root, workspace)
            version = self._run([str(executable), "version"], workspace, environment)
            require(version.returncode == 0 and version.stdout.strip() == GITLEAKS_VERSION, f"Gitleaks version must be {GITLEAKS_VERSION}.")
            report = workspace / "findings.json"
            ignore = workspace / "ignore"
            ignore.write_bytes(b"")
            result = self._run(
                [
                    str(executable),
                    "dir",
                    str(root),
                    "--config",
                    str(config),
                    "--redact=100",
                    "--no-banner",
                    "--no-color",
                    "--log-level",
                    "error",
                    "--ignore-gitleaks-allow",
                    "--gitleaks-ignore-path",
                    str(ignore),
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report),
                ],
                workspace,
                environment,
            )
            require(result.returncode in {0, 1}, "Gitleaks source-tree scan failed.")
            findings = self._findings(report, root, names)
            require((result.returncode == 1) == bool(findings), "Gitleaks result/report disagreement.")
        require(
            repository_files(root) == names and all(sha256(regular_file(root, name).read_bytes()) == digest for name, digest in before.items()),
            "Public tree changed during Gitleaks scan.",
        )
        require(sha256(config.read_bytes()) == CONFIG_SHA256, "Gitleaks configuration changed during scanning.")
        evidence: dict[str, object] = {
            "scanner": "gitleaks",
            "version": GITLEAKS_VERSION,
            "config_sha256": CONFIG_SHA256,
            "status": "failed" if findings else "clean",
            "findings": findings,
        }
        if output is not None:
            (output / "gitleaks-summary.json").write_bytes(canonical_json(evidence))
        require(not findings, "Gitleaks secret finding: " + "; ".join(f"{item['path']}:{item['line']} ({item['rule']})" for item in findings[:5]))
        return evidence

    def _run(self, arguments: list[str], workspace: Path, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(arguments, cwd=workspace, env=environment, capture_output=True, text=True, timeout=180, check=False)  # noqa: S603
        except (OSError, subprocess.SubprocessError, UnicodeError):
            message = "Gitleaks executable could not complete safely."
            raise ValueError(message) from None

    def _findings(self, report: Path, root: Path, names: tuple[str, ...]) -> list[dict[str, object]]:
        try:
            records = json.loads(report.read_bytes(), object_pairs_hook=self._unique)
            require(isinstance(records, list), "Invalid scanner report.")
            findings = []
            for record in records:
                require(isinstance(record, dict), "Invalid scanner finding.")
                path = Path(record["File"])
                name = path.relative_to(root).as_posix() if path.is_absolute() else path.as_posix()
                relative_path(name)
                require(name in names and re.fullmatch(r"[a-z0-9_-]{1,80}", record["RuleID"]) is not None, "Invalid scanner finding identity.")
                require(type(record["StartLine"]) is int and record["StartLine"] > 0, "Invalid scanner finding line.")
                findings.append({"path": name, "rule": record["RuleID"], "line": record["StartLine"]})
            return sorted(findings, key=lambda item: (str(item["path"]), str(item["rule"]), int(str(item["line"]))))
        except (OSError, ValueError, TypeError, KeyError, UnicodeError):
            message = "Gitleaks report could not be parsed safely."
            raise ValueError(message) from None

    def _unique(self, pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "Duplicate scanner report field.")
            result[key] = value
        return result
