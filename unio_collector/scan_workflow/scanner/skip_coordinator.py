from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scan_workflow.scanner.child_runner_factory import (
    ScannerChildRunnerFactory,
)

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner import ScannerRunner
    from unio_collector.scan_workflow.scanner.precheck_contract import (
        ScannerSkipRuntimeContract,
    )
    from unio_collector.scan_workflow.scanner.result_builder import (
        ScannerScheduleResultBuilder,
    )
    from unio_collector.scan_workflow.scanner.runtime.dependencies import (
        ScannerRuntimeDependencies,
    )
    from unio_collector.scan_workflow.schedule_helpers import ScannerScheduleHelper
    from unio_collector.scan_workflow.service.usage.precheck import (
        ServiceUsagePrecheckDecision,
    )
    from unio_collector.scanners.scanner.result import ScannerExecutionResult


class ScannerSkipCoordinator:
    """Create and notify scheduler skip results for scanner stages."""

    def __init__(  # noqa: D107
        self,
        *,
        runner: ScannerSkipRuntimeContract,
        dependencies: ScannerRuntimeDependencies,
        schedule_helpers: ScannerScheduleHelper,
        result_builder: ScannerScheduleResultBuilder,
    ) -> None:
        self.runner = runner
        self.dependencies = dependencies
        self.schedule_helpers = schedule_helpers
        self.result_builder = result_builder
        self.child_runner_factory = ScannerChildRunnerFactory()

    def get_service_precheck_decision(
        self,
        scanner_id: str,
    ) -> ServiceUsagePrecheckDecision:
        """Return and record the service-usage precheck decision."""
        schedule_state = self.runner.schedule_state
        decision = schedule_state.service_usage_precheck_policy.should_run(
            scanner_id,
            self.runner.output_state.service_deltas,
        )
        if decision.configured_service_patterns:
            schedule_state.service_usage_precheck_decisions.append(decision)
        return decision

    def record_service_precheck_skip_if_needed(
        self,
        scanner_id: str,
        *,
        scanner_index: int | None,
    ) -> bool:
        """Record a service-precheck skip when the scanner should not run."""
        decision = self.get_service_precheck_decision(scanner_id)
        if decision.should_run:
            return False
        result = self._build_service_precheck_skipped_result(
            scanner_id,
            decision,
        )
        self.runner.output_state.results.append(result)
        self.schedule_helpers.notify_skipped_scanner(
            result,
            scanner_index=scanner_index,
        )
        return True

    def record_dependency_skipped_scanner(
        self,
        scanner_id: str,
        *,
        dependency_id: str,
        scanner_index: int | None,
    ) -> None:
        """Record a dependency skip on the primary scheduler runner."""
        result = self.schedule_helpers.build_dependency_skipped_result(
            scanner_id,
            dependency_id=dependency_id,
        )
        self.runner.output_state.results.append(result)
        self.schedule_helpers.notify_skipped_scanner(
            result,
            scanner_index=scanner_index,
        )

    def add_dependency_skipped_child_result(
        self,
        child: ScannerRunner,
        scanner_id: str,
        *,
        dependency_id: str,
        scanner_index: int | None,
    ) -> None:
        """Record a dependency skip on a child runner and notify progress."""
        result = self.schedule_helpers.build_dependency_skipped_result(
            scanner_id,
            dependency_id=dependency_id,
        )
        child.output_state.results.append(result)
        self.schedule_helpers.notify_skipped_scanner(
            result,
            scanner_index=scanner_index,
        )

    def build_precheck_skipped_runner(
        self,
        scanner_id: str,
        decision: ServiceUsagePrecheckDecision,
        *,
        dependent_scanner_ids: tuple[str, ...],
        scanner_index: int | None,
        scanner_indexes: dict[str, int],
    ) -> ScannerRunner:
        """Build a child runner containing precheck and dependent skip results."""
        child = self.child_runner_factory.create_child_runner(
            parent=self.runner,
            progress=None,
            scanner_total=self.dependencies.scanner_total,
        )
        skipped = self._build_service_precheck_skipped_result(scanner_id, decision)
        child.output_state.results.append(skipped)
        self.schedule_helpers.notify_skipped_scanner(
            skipped,
            scanner_index=scanner_index,
        )
        for dependent_id in dependent_scanner_ids:
            self.add_dependency_skipped_child_result(
                child,
                dependent_id,
                dependency_id=scanner_id,
                scanner_index=scanner_indexes.get(dependent_id),
            )
        return child

    def _build_service_precheck_skipped_result(
        self,
        scanner_id: str,
        decision: ServiceUsagePrecheckDecision,
    ) -> ScannerExecutionResult:
        return self.result_builder.build_service_precheck_skipped_result(
            scanner_id=scanner_id,
            decision=decision,
        )
