"""Unio Collector local-first AWS evidence collection package."""

from __future__ import annotations

import tomllib
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as metadata_version
from pathlib import Path

__all__ = ["__version__"]


def _resolve_pyproject_version() -> str:
    pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
    try:
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return "0+unknown"

    project = data.get("project")
    if not isinstance(project, dict):
        return "0+unknown"
    resolved = project.get("version")
    if not isinstance(resolved, str):
        return "0+unknown"
    return resolved


def _resolve_version() -> str:
    for distribution in ("unio_collector", "unio-collector"):
        try:
            return metadata_version(distribution)
        except PackageNotFoundError:
            continue
    return _resolve_pyproject_version()


__version__ = _resolve_version()
