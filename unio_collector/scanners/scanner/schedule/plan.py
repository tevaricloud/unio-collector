from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.schedule.stage import ScannerScheduleStage


@dataclass(frozen=True)
class ScannerSchedulePlan:
    """Dependency-aware scanner execution plan."""

    stages: tuple[ScannerScheduleStage, ...]
    max_workers: int
    concurrency_enabled: bool

    def convert_to_dict(self) -> dict[str, object]:  # noqa: D102
        return {
            "max_workers": self.max_workers,
            "concurrency_enabled": self.concurrency_enabled,
            "stages": [stage.convert_to_dict() for stage in self.stages],
        }
