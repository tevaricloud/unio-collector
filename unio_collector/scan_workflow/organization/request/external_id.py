from __future__ import annotations

# ruff: noqa: D100,TC003
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExternalIdReference:
    """Reference an external ID without retaining its value."""

    environment_variable: str | None = None
    file: Path | None = None
