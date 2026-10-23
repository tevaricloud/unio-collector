"""Local build identification, without granting authenticity or release status."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

from unio_collector import __version__

MAX_INSTALLER_REVISION = 999

BUILD_IDENTITY_FILE = "collector-build.json"


class CollectorBuildIdentity:
    """Identify the native executable actually running, or a Python install."""

    def read(self) -> dict[str, object]:
        """Fail closed for absent/malformed frozen metadata; do not guess a SHA."""
        if not getattr(sys, "frozen", False):
            return {"application_version": __version__, "kind": "python", "source_commit": None}
        executable = Path(sys.executable).resolve()
        payload = json.loads((executable.parent / BUILD_IDENTITY_FILE).read_text(encoding="utf-8"))
        fields = {"application_version", "source_commit", "wheel_sha256", "installer_revision", "installer_version", "channel", "schema_version"}
        if not isinstance(payload, dict) or set(payload) != fields or payload["schema_version"] != 1 or payload["application_version"] != __version__:
            message = "Native build identity is missing or inconsistent."
            raise ValueError(message)
        if any(
            not isinstance(payload[key], str) or not re.fullmatch(pattern, payload[key])
            for key, pattern in (("source_commit", r"[0-9a-f]{40}"), ("wheel_sha256", r"[0-9a-f]{64}"), ("installer_version", r"[0-9]+\.[0-9]+\.[0-9]+"))
        ):
            message = "Native build identity contains invalid hashes/version."
            raise ValueError(message)
        if (
            type(payload["installer_revision"]) is not int
            or not 1 <= payload["installer_revision"] <= MAX_INSTALLER_REVISION
            or payload["channel"] not in {"test", "release"}
        ):
            message = "Native build identity contains invalid revision/channel."
            raise ValueError(message)
        return {**payload, "kind": "native", "executable": str(executable), "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest()}

    def label(self) -> str:
        """Show the application version plus installer revision and source SHA."""
        value = self.read()
        if value["kind"] == "python":
            return f"Unio Collector {__version__}"
        return f"Unio Collector {__version__} (build {value['installer_revision']}, {str(value['source_commit'])[:12]})"
