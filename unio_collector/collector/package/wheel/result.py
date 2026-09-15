from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class CollectorWheelBuildResult:
    """Validated collector-only wheel build output."""

    wheel_path: Path
    source_file_count: int
    wheel_member_count: int
    validation_status: str
