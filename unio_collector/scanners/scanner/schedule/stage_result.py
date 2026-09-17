from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass
class ScannerScheduleStageResult:
    """Runtime result for one scanner scheduler stage."""

    name: str
    scanner_ids: list[str]
    concurrent: bool
    max_workers: int
    started_at: datetime
    completed_at: datetime
    failed_scanners: list[str] = field(default_factory=list)
    attached_dependents: dict[str, list[str]] = field(default_factory=dict)
    submitted_scanner_count: int | None = None
    precheck_skipped_scanner_count: int = 0
    dependency_skipped_scanner_count: int = 0
    submission_order: list[str] = field(default_factory=list)

    def convert_to_dict(self) -> dict[str, object]:  # noqa: D102
        result = {
            "name": self.name,
            "scanner_ids": list(self.scanner_ids),
            "concurrent": self.concurrent,
            "max_workers": self.max_workers,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_ms": int(
                (self.completed_at - self.started_at).total_seconds() * 1000,
            ),
            "failed_scanners": list(self.failed_scanners),
        }
        if self.submitted_scanner_count is not None:
            result["submitted_scanner_count"] = self.submitted_scanner_count
        if self.submission_order:
            result["submission_order"] = list(self.submission_order)
        if self.precheck_skipped_scanner_count:
            result["precheck_skipped_scanner_count"] = self.precheck_skipped_scanner_count
        if self.dependency_skipped_scanner_count:
            result["dependency_skipped_scanner_count"] = self.dependency_skipped_scanner_count
        if self.attached_dependents:
            result["attached_dependents"] = {
                scanner_id: list(dependent_ids)
                for scanner_id, dependent_ids in sorted(
                    self.attached_dependents.items(),
                )
            }
        return result
