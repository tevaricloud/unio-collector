"""Isolated subprocess execution with retained, bounded validation evidence."""

from __future__ import annotations

import os
import re
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

MAX_DIAGNOSTIC_LINE_LENGTH = 600


class RepositoryProcess:
    """Route every subprocess cache and transient output outside source."""

    def __init__(self, workspace: Path, output: Path) -> None:
        """Keep temporary state separate from retained logs."""
        self.workspace = workspace
        self.output = output
        self.steps: list[dict[str, object]] = []

    def environment(self, *, source_sha: str | None = None) -> dict[str, str]:
        """Remove source injection and disable live AWS access for validation."""
        environment = os.environ.copy()
        for key in (
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONSTARTUP",
            "AWS_PROFILE",
            "AWS_DEFAULT_PROFILE",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        ):
            environment.pop(key, None)
        environment.update(
            {
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PIP_NO_CACHE_DIR": "1",
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                "PIP_NO_INPUT": "1",
                "PIP_CACHE_DIR": str(self.workspace / "pip-cache"),
                "RUFF_NO_CACHE": "1",
                "XDG_CACHE_HOME": str(self.workspace / "cache"),
                "PYTHONPYCACHEPREFIX": str(self.workspace / "bytecode"),
                "PYINSTALLER_CONFIG_DIR": str(self.workspace / "pyinstaller"),
                "TEMP": str(self.workspace),
                "TMP": str(self.workspace),
                "TMPDIR": str(self.workspace),
                "UNIO_COLLECTOR_EXTERNAL_TEMP_ROOT": str(self.workspace),
                "UNIO_COLLECTOR_LIVE_AWS_TESTS": "0",
                "UNIO_COLLECTOR_ALLOW_CHARGEABLE_TESTS": "0",
                "AWS_EC2_METADATA_DISABLED": "true",
                "AWS_SHARED_CREDENTIALS_FILE": str(self.workspace / "absent-credentials"),
                "AWS_CONFIG_FILE": str(self.workspace / "absent-config"),
            }
        )
        if source_sha is not None:
            environment["UNIO_COLLECTOR_VALIDATION_SOURCE_SHA"] = source_sha
        return environment

    def run(self, name: str, command: list[str], *, cwd: Path, source_sha: str | None = None) -> None:
        """Run one required check and retain its exit code and log."""
        log = self.output / f"{name}.log"
        with log.open("w", encoding="utf-8") as stream:
            completed = subprocess.run(command, cwd=cwd, env=self.environment(source_sha=source_sha), stdout=stream, stderr=subprocess.STDOUT, check=False)  # noqa: S603
        diagnostic = self._failure_diagnostic(name, log) if completed.returncode else None
        self.steps.append({"name": name, "exit_code": completed.returncode, "log": log.name, "diagnostic": diagnostic})
        if completed.returncode:
            message = f"Standalone {name} failed ({completed.returncode}); see {log}."
            if diagnostic:
                message = f"{message} Diagnostic: {diagnostic}"
            raise RuntimeError(message)

    @staticmethod
    def _failure_diagnostic(name: str, log: Path) -> str | None:
        """Return only bounded, source-text-free diagnostics for reviewed steps."""
        try:
            lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return None
        if name == "ruff":
            safe = [line.strip() for line in lines if re.fullmatch(r"[A-Za-z0-9_./\\-]+:\d+:\d+: [A-Z][A-Z0-9]+ .{1,240}", line.strip())]
        elif name.endswith("-driver"):
            safe = [
                line.strip()
                for line in lines
                if line.startswith("Standalone repository operation failed: Standalone ruff failed (") and len(line) <= MAX_DIAGNOSTIC_LINE_LENGTH
            ]
        else:
            safe = []
        return " | ".join(safe[-5:]) or None
