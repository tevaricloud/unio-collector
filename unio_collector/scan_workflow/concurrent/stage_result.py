from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ConcurrentStageRunResult:
    """Result summary from a concurrent scanner scheduler stage."""

    failed_scanners: list[str]
    max_workers_used: int
    submitted_scanner_count: int
    precheck_skipped_scanner_count: int
    dependency_skipped_scanner_count: int
    submission_order: list[str]
