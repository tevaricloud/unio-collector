from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class LauncherSelection:
    """Collector choices mapped directly to existing CLI arguments."""

    output: Path
    profile: str = ""
    scanner_ids: tuple[str, ...] = ()
    preset: str = ""
    detail_profile: str = ""
    pillars: tuple[str, ...] = ()
    allow_chargeable_scanners: bool = False
    include_cost_data: bool = True
    check_identity: bool = False


__all__ = ["LauncherSelection"]
