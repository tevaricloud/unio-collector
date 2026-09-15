from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scan_workflow.scanner.result_builder import (
    ScannerScheduleResultBuilder,
)
from unio_collector.scan_workflow.scanner.stage.executor import (
    ScannerStageExecutor,
)
from unio_collector.scan_workflow.schedule_helpers import ScannerScheduleHelper
from unio_collector.scanners.execution import (
    ScannerExecutionPlanner,
)
from unio_collector.scanners.registry.catalog import get_scanner

if TYPE_CHECKING:
    from unio_collector.scan_workflow.scanner.operation import ScannerOperation
    from unio_collector.scan_workflow.scanner.orchestration_contract import (
        ScannerScheduleRuntimeContract,
    )
    from unio_collector.scan_workflow.scanner.runtime.dependencies import (
        ScannerRuntimeDependencies,
    )


class ScannerScheduleService:
    """Execute scanner stages while preserving per-scanner failure isolation."""

    def __init__(  # noqa: D107
        self,
        runner: ScannerScheduleRuntimeContract,
        dependencies: ScannerRuntimeDependencies,
        scanner_operation: ScannerOperation,
    ) -> None:
        self.runner = runner
        self.dependencies = dependencies
        self.result_builder = ScannerScheduleResultBuilder()
        self.schedule_helpers = ScannerScheduleHelper(
            runner=runner,
            dependencies=dependencies,
            result_builder=self.result_builder,
        )
        self.stage_executor = ScannerStageExecutor(
            runner=runner,
            dependencies=dependencies,
            schedule_helpers=self.schedule_helpers,
            result_builder=self.result_builder,
            scanner_operation=scanner_operation,
        )

    def run_many(self, scanner_ids: tuple[str, ...] | list[str]) -> None:
        """Plan and run scanner stages for the requested scanner IDs."""
        runtime_config = self.runner.runtime_state.runtime_config
        planner = ScannerExecutionPlanner(
            max_workers=runtime_config.scanner_max_workers,
            concurrency_enabled=runtime_config.scanner_concurrency_enabled,
            phase_resolver=self.get_scanner_execution_phase,
            dependency_resolver=self.get_scanner_dependencies,
        )
        ordered_ids = tuple(scanner_ids)
        schedule_state = self.runner.schedule_state
        schedule_state.scheduler_plan = planner.build_plan(ordered_ids)
        scanner_indexes = {scanner_id: index for index, scanner_id in enumerate(ordered_ids, start=1)}
        for stage in schedule_state.scheduler_plan.stages:
            schedule_state.scheduler_stage_results.append(
                self.stage_executor.run_stage(stage, scanner_indexes),
            )

    def get_scanner_execution_phase(self, scanner_id: str) -> str:
        """Return the configured execution phase for a scanner."""
        return get_scanner(scanner_id).execution_phase

    def get_scanner_dependencies(self, scanner_id: str) -> tuple[str, ...]:
        """Return scanner IDs that must run before this scanner."""
        return get_scanner(scanner_id).depends_on_scanner_ids
