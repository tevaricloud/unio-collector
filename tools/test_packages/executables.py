"""Resolve host tools without searching a download directory or relative PATH."""

from __future__ import annotations

import os
from pathlib import Path

from tools.collector_repository.paths import require


def host_executable(name: str) -> Path:
    """Resolve only the finite existing host tools from absolute PATH entries."""
    require(name in {"git", "gh", "powershell"}, "Unapproved host executable.")
    cwd = Path.cwd().resolve()
    source = Path(__file__).resolve().parents[2]
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        directory = Path(entry)
        if not directory.is_absolute():
            continue
        directory = directory.resolve()
        if directory in (cwd, source) or directory.is_relative_to(cwd) or directory.is_relative_to(source):
            continue
        path = directory / (name + ".exe" if os.name == "nt" else name)
        if path.is_file() and not path.is_symlink() and os.access(path, os.X_OK):
            return path
    message = f"Existing trusted host tool is unavailable: {name}"
    raise ValueError(message)
