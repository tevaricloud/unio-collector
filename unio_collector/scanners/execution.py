from __future__ import annotations  # noqa: D100

from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from unio_collector.scanners.scanner.execution_types import (
    PHASE_STAGE_NAMES,
    VALID_EXECUTION_PHASES,
    ScannerDependencyResolver,
    ScannerPhaseResolver,
)
from unio_collector.scanners.scanner.schedule.plan import ScannerSchedulePlan
from unio_collector.scanners.scanner.schedule.stage import ScannerScheduleStage
from unio_collector.scanners.scanner.schedule.stage_result import ScannerScheduleStageResult

if TYPE_CHECKING:
    from collections.abc import Iterable

    from unio_collector.scanners.scanner.types import ScannerExecutionPhase

__all__ = [
    "ScannerExecutionPlanner",
    "ScannerSchedulePlan",
    "ScannerScheduleStage",
    "ScannerScheduleStageResult",
    "get_utc_now",
]


class ScannerExecutionPlanner:
    """Builds dependency-aware scanner execution stages."""

    def __init__(  # noqa: D107
        self,
        *,
        max_workers: int,
        concurrency_enabled: bool,
        phase_resolver: ScannerPhaseResolver | None = None,
        dependency_resolver: ScannerDependencyResolver | None = None,
    ) -> None:
        if max_workers <= 0:
            msg = "Scanner max_workers must be a positive integer."
            raise ValueError(msg)
        self.max_workers = max_workers
        self.concurrency_enabled = concurrency_enabled
        self.phase_resolver = phase_resolver or self._get_default_execution_phase
        self.dependency_resolver = dependency_resolver or (self._get_default_dependencies)

    def build_plan(self, scanner_ids: Iterable[str]) -> ScannerSchedulePlan:  # noqa: D102
        ordered_ids = tuple(dict.fromkeys(scanner_ids))
        grouped_ids = self._group_scanner_ids_by_phase(ordered_ids)
        attached_dependents = self._build_attached_dependents(grouped_ids)
        attached_dependent_ids = {dependent_id for dependent_ids in attached_dependents.values() for dependent_id in dependent_ids}
        remaining_dependent_ids = tuple(scanner_id for scanner_id in grouped_ids["dependent"] if scanner_id not in attached_dependent_ids)
        stages = tuple(
            stage
            for stage in (
                ScannerScheduleStage(
                    name=PHASE_STAGE_NAMES["baseline"],
                    scanner_ids=tuple(grouped_ids["baseline"]),
                    concurrent=False,
                ),
                ScannerScheduleStage(
                    name=PHASE_STAGE_NAMES["independent"],
                    scanner_ids=tuple(grouped_ids["independent"]),
                    concurrent=(self.concurrency_enabled and len(grouped_ids["independent"]) > 1),
                    attached_dependents=attached_dependents,
                ),
                ScannerScheduleStage(
                    name=PHASE_STAGE_NAMES["dependent"],
                    scanner_ids=remaining_dependent_ids,
                    concurrent=False,
                ),
            )
            if not stage.is_empty()
        )
        return ScannerSchedulePlan(
            stages=stages,
            max_workers=self.max_workers,
            concurrency_enabled=self.concurrency_enabled,
        )

    def _group_scanner_ids_by_phase(
        self,
        ordered_ids: tuple[str, ...],
    ) -> dict[ScannerExecutionPhase, list[str]]:
        grouped_ids: dict[ScannerExecutionPhase, list[str]] = {
            "baseline": [],
            "independent": [],
            "dependent": [],
        }
        for scanner_id in ordered_ids:
            phase = self._get_scanner_execution_phase(scanner_id)
            grouped_ids[phase].append(scanner_id)
        return grouped_ids

    def _get_scanner_execution_phase(self, scanner_id: str) -> ScannerExecutionPhase:
        phase = self.phase_resolver(scanner_id)
        if phase not in VALID_EXECUTION_PHASES:
            msg = f"Scanner {scanner_id} has unsupported execution phase: {phase}"
            raise ValueError(
                msg,
            )
        return cast("ScannerExecutionPhase", phase)

    def _get_default_execution_phase(self, _scanner_id: str) -> ScannerExecutionPhase:
        return "independent"

    def _get_default_dependencies(self, _scanner_id: str) -> tuple[str, ...]:
        return ()

    def _build_attached_dependents(
        self,
        grouped_ids: dict[ScannerExecutionPhase, list[str]],
    ) -> dict[str, tuple[str, ...]]:
        if not self.concurrency_enabled:
            return {}

        independent_ids = set(grouped_ids["independent"])
        attached: dict[str, list[str]] = {}
        for dependent_id in grouped_ids["dependent"]:
            dependencies = self.dependency_resolver(dependent_id)
            if len(dependencies) != 1:
                continue
            dependency_id = dependencies[0]
            if dependency_id not in independent_ids:
                continue
            attached.setdefault(dependency_id, []).append(dependent_id)
        return {scanner_id: tuple(dependent_ids) for scanner_id, dependent_ids in attached.items()}


def get_utc_now() -> datetime:  # noqa: D103
    return datetime.now(UTC)
