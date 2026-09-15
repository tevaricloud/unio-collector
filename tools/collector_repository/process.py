"""Isolated subprocess execution with retained, bounded validation evidence."""

from __future__ import annotations

import os
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class RepositoryProcess:
    """Route every subprocess cache and transient output outside source."""

    def __init__(self, workspace: Path, output: Path) -> None:
        """Keep temporary state separate from retained logs."""
        self.workspace = workspace
        self.output = output
        self.steps: list[dict[str, object]] = []

    def environment(self) -> dict[str, str]:
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
        return environment

    def run(self, name: str, command: list[str], *, cwd: Path) -> None:
        """Run one required check and retain its exit code and log."""
        log = self.output / f"{name}.log"
        with log.open("w", encoding="utf-8") as stream:
            completed = subprocess.run(command, cwd=cwd, env=self.environment(), stdout=stream, stderr=subprocess.STDOUT, check=False)  # noqa: S603
        self.steps.append({"name": name, "exit_code": completed.returncode, "log": log.name})
        if completed.returncode:
            message = f"Standalone {name} failed ({completed.returncode}); see {log}."
            raise RuntimeError(message)
