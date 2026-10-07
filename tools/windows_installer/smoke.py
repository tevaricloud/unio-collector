"""Correlate the executable actually launched with the native build metadata."""

from __future__ import annotations

import hashlib
from pathlib import Path


def verify_launched_identity(actual: dict[str, object], expected: dict[str, object], executable: Path) -> None:
    """Reject stale executables even when their application version agrees."""
    if (
        any(actual.get(key) != value for key, value in expected.items())
        or actual.get("kind") != "native"
        or Path(str(actual.get("executable"))).resolve() != executable.resolve()
        or actual.get("executable_sha256") != hashlib.sha256(executable.read_bytes()).hexdigest()
    ):
        message = "Launched native executable does not match this exact build."
        raise ValueError(message)
