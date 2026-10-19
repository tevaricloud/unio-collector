"""Isolated subprocess execution with retained, bounded validation evidence."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

MAX_DIAGNOSTIC_LINE_LENGTH = 600
PROGRESS_INTERVAL_SECONDS = 60


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
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            message = "Invalid validation stage name."
            raise ValueError(message)
        log = self.output / f"{name}.log"
        started = time.monotonic()
        step: dict[str, object] = {
            "name": name,
            "status": "running",
            "started_at": datetime.now(UTC).isoformat(),
            "exit_code": None,
            "log": log.name,
            "diagnostic": None,
        }
        self.steps.append(step)
        self._progress(step, started, log)
        try:
            with (
                log.open("w", encoding="utf-8") as stream,
                subprocess.Popen(command, cwd=cwd, env=self.environment(source_sha=source_sha), stdout=stream, stderr=subprocess.STDOUT) as child,  # noqa: S603
            ):
                while True:
                    try:
                        returncode = child.wait(timeout=PROGRESS_INTERVAL_SECONDS)
                        break
                    except subprocess.TimeoutExpired:
                        self._progress(step, started, log)
        except OSError:
            step["status"] = "launch-failed"
            step["finished_at"] = datetime.now(UTC).isoformat()
            self._progress(step, started, log)
            raise
        diagnostic = self._failure_diagnostic(name, log) if returncode else None
        step.update(exit_code=returncode, diagnostic=diagnostic, status="failed" if returncode else "passed", finished_at=datetime.now(UTC).isoformat())
        self._progress(step, started, log)
        if returncode:
            message = f"Standalone {name} failed ({returncode}); see {log}."
            if diagnostic:
                message = f"{message} Diagnostic: {diagnostic}"
            raise RuntimeError(message)

    def _progress(self, step: dict[str, object], started: float, log: Path) -> None:
        """Publish stage metadata only; command arguments and log contents stay private."""
        elapsed = round(time.monotonic() - started, 3)
        size = log.stat().st_size if log.exists() else 0
        step.update(elapsed_seconds=elapsed, log_bytes=size, observed_at=datetime.now(UTC).isoformat())
        checkpoint = self.output / "process-progress.json"
        temporary = checkpoint.with_suffix(".tmp")
        temporary.write_text(json.dumps({"steps": self.steps}, indent=2) + "\n", encoding="utf-8")
        temporary.replace(checkpoint)
        sys.stdout.write(f"Standalone stage {step['name']}: {step['status']}; elapsed={elapsed:.1f}s; retained_log_bytes={size}\n")
        sys.stdout.flush()

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
