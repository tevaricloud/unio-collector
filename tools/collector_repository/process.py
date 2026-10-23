"""Isolated subprocess execution with retained, bounded validation evidence."""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

MAX_DIAGNOSTIC_LINE_LENGTH = 600
PROGRESS_INTERVAL_SECONDS = 60
VALIDATION_DRIVER_TIMEOUT_SECONDS = 350 * 60
STAGE_TIMEOUT_SECONDS = {"tests": 345 * 60, "native-build": 60 * 60, "native-installer": 20 * 60, "native-malware": 20 * 60}


class RepositoryProcess:
    """Route every subprocess cache and transient output outside source."""

    def __init__(self, workspace: Path, output: Path) -> None:
        """Keep temporary state separate from retained logs."""
        self.workspace = workspace
        self.output = output
        self.steps: list[dict[str, object]] = []
        deadline = os.environ.get("UNIO_VALIDATION_DEADLINE_EPOCH")
        self.deadline = int(deadline) if deadline is not None else None

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

    def run(self, name: str, command: list[str], *, cwd: Path, source_sha: str | None = None, timeout_seconds: float | None = None) -> None:
        """Run one required check and retain its exit code and log."""
        timeout = self._timeout(name, timeout_seconds)
        log = self.output / f"{name}.log"
        started = time.monotonic()
        step: dict[str, object] = {
            "name": name,
            "status": "running",
            "started_at": datetime.now(UTC).isoformat(),
            "exit_code": None,
            "log": log.name,
            "diagnostic": None,
            "timeout_seconds": timeout,
        }
        self.steps.append(step)
        self._progress(step, started, log)
        if timeout == 0:
            step.update(status="timed-out", finished_at=datetime.now(UTC).isoformat())
            self._progress(step, started, log)
            message = "Job validation budget expired before stage launch."
            raise RuntimeError(message)
        try:
            with (
                log.open("w", encoding="utf-8") as stream,
                subprocess.Popen(  # noqa: S603
                    command, cwd=cwd, env=self.environment(source_sha=source_sha), stdout=stream, stderr=subprocess.STDOUT, start_new_session=os.name != "nt"
                ) as child,
                self._signals(),
            ):
                try:
                    while True:
                        remaining = self._remaining(name, timeout, started)
                        try:
                            returncode = child.wait(timeout=min(PROGRESS_INTERVAL_SECONDS, remaining))
                            break
                        except subprocess.TimeoutExpired:
                            self._progress(step, started, log)
                except (KeyboardInterrupt, InterruptedError, subprocess.TimeoutExpired) as exc:
                    step.update(status="timed-out" if isinstance(exc, subprocess.TimeoutExpired) else "cancelled", finished_at=datetime.now(UTC).isoformat())
                    self._progress(step, started, log)
                    step["termination"] = self._stop(child)
                    step["exit_code"] = child.returncode
                    self._progress(step, started, log)
                    message = f"Standalone {name} {step['status']}; see retained stage log."
                    raise RuntimeError(message) from exc
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

    def _timeout(self, name: str, timeout_seconds: float | None) -> float:
        """Apply a stage cap and the remaining overall diagnostic reserve."""
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            message = "Invalid validation stage name."
            raise ValueError(message)
        timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else STAGE_TIMEOUT_SECONDS.get(name, VALIDATION_DRIVER_TIMEOUT_SECONDS if name.endswith("-driver") else 600)
        )
        if timeout <= 0:
            message = "Stage timeout must be positive."
            raise ValueError(message)
        if self.deadline is not None:
            timeout = min(timeout, max(0, self.deadline - time.time()))
        return timeout

    @staticmethod
    def _remaining(name: str, timeout: float, started: float) -> float:
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise subprocess.TimeoutExpired(name, timeout)
        return remaining

    @staticmethod
    def _stop(child: subprocess.Popen[bytes]) -> str:
        """Bound teardown of the task's subprocess tree before diagnostic upload."""
        termination = "process-tree"
        if os.name == "nt":
            executable = shutil.which("taskkill")
            try:
                if executable is None:
                    raise FileNotFoundError
                result = subprocess.run([executable, "/PID", str(child.pid), "/T", "/F"], capture_output=True, timeout=10, check=False)  # noqa: S603
                if result.returncode and child.poll() is None:
                    child.kill()
                    termination = "direct-child-fallback"
            except (OSError, subprocess.TimeoutExpired):
                child.kill()
                termination = "direct-child-fallback"
        else:
            with suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                child.kill()
            else:
                os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
        return termination

    @staticmethod
    @contextmanager
    def _signals() -> Iterator[None]:
        """Turn runner termination into retained cancellation metadata and teardown."""
        previous = {}

        def interrupt(_signum: int, _frame: object) -> None:
            message = "Runner cancellation requested."
            raise InterruptedError(message)

        numbers = [signal.SIGTERM]
        if sys.platform == "win32":
            numbers.append(signal.SIGBREAK)
        if threading.current_thread() is threading.main_thread():
            for number in numbers:
                previous[number] = signal.signal(number, interrupt)
        try:
            yield
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)

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
