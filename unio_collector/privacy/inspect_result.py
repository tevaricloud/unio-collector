from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class PrivacyInspectResult:
    """Protected bundle inspection result."""

    path: Path
    protected: bool
    validation_passed: bool
    summary: dict[str, object]
    errors: tuple[str, ...] = ()
