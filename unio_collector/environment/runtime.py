"""Process-scoped environment-classifier configuration."""

from __future__ import annotations

from pathlib import Path

_ALIAS_FILE: Path | None = None


def configure_environment_alias_file(value: str | Path | None) -> None:
    """Set the optional local alias file for this single-command process."""
    global _ALIAS_FILE  # noqa: PLW0603
    _ALIAS_FILE = Path(value) if value else None


def current_environment_alias_file() -> Path | None:
    """Return the current invocation's local alias file."""
    return _ALIAS_FILE
