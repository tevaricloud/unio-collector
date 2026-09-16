from __future__ import annotations  # noqa: D100

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any

from unio_collector.scan_workflow.concurrent.stage_result import (
    ConcurrentStageRunResult,
)
from unio_collector.scan_workflow.progress import ScanProgressEvent
from unio_collector.scan_workflow.runner.snapshot import ScannerRunnerOutputSnapshot
from unio_collector.scan_workflow.scanner.attempt import (
    ScannerAttemptContext,
    ScannerAttemptOutcomeReason,
    ScannerAttemptSupervisor,
    ScannerAttemptSupervisorContract,
)
from unio_collector.scan_workflow.scanner.child_runner_factory import (
    ScannerChildRunnerFactory,
)
from unio_collector.scan_workflow.scanner.skip_coordinator import ScannerSkipCoordinator
from unio_collector.scanners.execution import (
    ScannerScheduleStage,
    ScannerScheduleStageResult,
    get_utc_now,
)
from unio_collector.scanners.registry.catalog import get_scanner

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner import ScannerRunner
    from unio_collector.scan_workflow.scanner.executor_contract import (
        ScannerStageRuntimeContract,
    )
    from unio_collector.scan_workflow.scanner.operation import ScannerOperation
    from unio_collector.scan_workflow.scanner.result_builder import (
        ScannerScheduleResultBuilder,
    )
    from unio_collector.scan_workflow.scanner.runtime.dependencies import (
        ScannerRuntimeDependencies,
    )
    from unio_collector.scan_workflow.schedule_helpers import ScannerScheduleHelper
    from unio_collector.scanners.scanner.result import ScannerExecutionResult


class ScannerStageExecutor:
    """Run one scanner schedule stage and return the scheduler summary."""

    def __init__(  # noqa: D107
        self,
        *,
        runner: ScannerStageRuntimeContract,
        dependencies: ScannerRuntimeDependencies,
        schedule_helpers: ScannerScheduleHelper,
        result_builder: ScannerScheduleResultBuilder,
        scanner_operation: ScannerOperation,
    ) -> None:
        self.runner = runner
        self.dependencies = dependencies
        self.schedule_helpers = schedule_helpers
        self.result_builder = result_builder
        self.child_runner_factory = ScannerChildRunnerFactory()
        self.scanner_operation = scanner_operation
        self.skip_coordinator = ScannerSkipCoordinator(
            runner=runner,
            dependencies=dependencies,
            schedule_helpers=schedule_helpers,
            result_builder=result_builder,
        )
        self.attempt_supervisor: ScannerAttemptSupervisorContract = ScannerAttemptSupervisor(
            runner.runtime_state.runtime_config.scanner_max_workers,
        )

    def run_stage(
        self,
        stage: ScannerScheduleStage,
        scanner_indexes: dict[str, int],
    ) -> ScannerScheduleStageResult:
        """Run one sequential or concurrent scanner schedule stage."""
        started_at = get_utc_now()
        failed_scanners: list[str] = []
        max_workers_used = 1
        submitted_scanner_count: int | None = None
        precheck_skipped_scanner_count = 0
        dependency_skipped_scanner_count = 0
        submission_order: list[str] = []
        if stage.concurrent:
            stage_run_result = self._run_concurrent_stage(stage, scanner_indexes)
            failed_scanners = stage_run_result.failed_scanners
            max_workers_used = stage_run_result.max_workers_used
            submitted_scanner_count = stage_run_result.submitted_scanner_count
            precheck_skipped_scanner_count = stage_run_result.precheck_skipped_scanner_count
            dependency_skipped_scanner_count = stage_run_result.dependency_skipped_scanner_count
            submission_order = stage_run_result.submission_order
        else:
            failed_scanners = self._run_sequential_stage(stage, scanner_indexes)
        completed_at = get_utc_now()
        return ScannerScheduleStageResult(
            name=stage.name,
            scanner_ids=list(stage.scanner_ids),
            concurrent=stage.concurrent,
            max_workers=max_workers_used,
            started_at=started_at,
            completed_at=completed_at,
            failed_scanners=failed_scanners,
            submitted_scanner_count=submitted_scanner_count,
            precheck_skipped_scanner_count=precheck_skipped_scanner_count,
            dependency_skipped_scanner_count=dependency_skipped_scanner_count,
            submission_order=submission_order,
            attached_dependents={scanner_id: list(dependent_ids) for scanner_id, dependent_ids in stage.attached_dependents.items()},
        )

    def _run_sequential_stage(
        self,
        stage: ScannerScheduleStage,
        scanner_indexes: dict[str, int],
    ) -> list[str]:
        failed_scanners: list[str] = []
        for scanner_id in stage.scanner_ids:
            scanner_chain = (
                scanner_id,
                *stage.attached_dependents.get(scanner_id, ()),
            )
            parent_skipped = False
            for chain_scanner_id in scanner_chain:
                if parent_skipped:
                    self.skip_coordinator.record_dependency_skipped_scanner(
                        chain_scanner_id,
                        dependency_id=scanner_id,
                        scanner_index=scanner_indexes.get(chain_scanner_id),
                    )
                    continue
                skipped = self.skip_coordinator.record_service_precheck_skip_if_needed(
                    chain_scanner_id,
                    scanner_index=scanner_indexes.get(chain_scanner_id),
                )
                if skipped:
                    parent_skipped = chain_scanner_id == scanner_id
                    continue
                child = self._run_isolated_scanner_chain(
                    chain_scanner_id,
                    (),
                    scanner_index=scanner_indexes.get(chain_scanner_id),
                    scanner_indexes=scanner_indexes,
                )
                self.schedule_helpers.merge_child_runner(child)
                result = self._get_merge_visible_results(child)[-1]
                if result.status in {"failed", "permission_denied"}:
                    failed_scanners.append(chain_scanner_id)
        return failed_scanners

    def _run_concurrent_stage(
        self,
        stage: ScannerScheduleStage,
        scanner_indexes: dict[str, int],
    ) -> ConcurrentStageRunResult:
        child_runners: dict[str, ScannerRunner] = {}
        runnable_scanner_ids: list[str] = []
        precheck_skipped_count = 0
        dependency_skipped_count = 0
        for scanner_id in stage.scanner_ids:
            decision = self.skip_coordinator.get_service_precheck_decision(scanner_id)
            if decision.should_run:
                runnable_scanner_ids.append(scanner_id)
                continue
            dependents = stage.attached_dependents.get(scanner_id, ())
            child_runners[scanner_id] = self.skip_coordinator.build_precheck_skipped_runner(
                scanner_id,
                decision,
                dependent_scanner_ids=dependents,
                scanner_index=scanner_indexes.get(scanner_id),
                scanner_indexes=scanner_indexes,
            )
            precheck_skipped_count += 1
            dependency_skipped_count += len(dependents)

        worker_count = min(
            self.runner.runtime_state.runtime_config.scanner_max_workers,
            len(runnable_scanner_ids),
        )
        submission_order = self._prioritize_concurrent_submission_order(
            runnable_scanner_ids,
            stage,
        )
        if runnable_scanner_ids:
            self._run_runnable_concurrent_scanners(
                submission_order,
                stage,
                scanner_indexes,
                child_runners,
                worker_count=worker_count,
            )

        failed_scanners: list[str] = []
        for scanner_id in stage.scanner_ids:
            child = child_runners[scanner_id]
            self.schedule_helpers.merge_child_runner(child)
            failed_scanners.extend(result.scanner_id for result in self._get_merge_visible_results(child) if result.status in {"failed", "permission_denied"})
        return ConcurrentStageRunResult(
            failed_scanners=failed_scanners,
            max_workers_used=worker_count,
            submitted_scanner_count=len(runnable_scanner_ids),
            precheck_skipped_scanner_count=precheck_skipped_count,
            dependency_skipped_scanner_count=dependency_skipped_count,
            submission_order=submission_order,
        )

    def _run_runnable_concurrent_scanners(
        self,
        submission_order: list[str],
        stage: ScannerScheduleStage,
        scanner_indexes: dict[str, int],
        child_runners: dict[str, ScannerRunner],
        *,
        worker_count: int,
    ) -> None:
        with ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="unio-collector-scanner",
        ) as executor:
            future_map = {}
            for scanner_id in submission_order:
                future_map[
                    executor.submit(
                        self._run_isolated_scanner_chain,
                        scanner_id,
                        stage.attached_dependents.get(scanner_id, ()),
                        scanner_indexes.get(scanner_id),
                        scanner_indexes,
                    )
                ] = scanner_id
            for future in as_completed(future_map):
                scanner_id = future_map[future]
                try:
                    child_runners[scanner_id] = future.result()
                except Exception as exc:  # noqa: BLE001
                    child_runners[scanner_id] = self.schedule_helpers.build_scheduler_failure_runner(
                        scanner_id,
                        exc,
                    )

    def _prioritize_concurrent_submission_order(
        self,
        runnable_scanner_ids: list[str],
        stage: ScannerScheduleStage,
    ) -> list[str]:
        original_positions = {scanner_id: index for index, scanner_id in enumerate(runnable_scanner_ids)}

        def sort_key(scanner_id: str) -> tuple[int, int, int]:
            dependent_count = len(stage.attached_dependents.get(scanner_id, ()))
            has_attached_dependents = 0 if dependent_count else 1
            return (
                has_attached_dependents,
                -dependent_count,
                original_positions[scanner_id],
            )

        return sorted(runnable_scanner_ids, key=sort_key)

    def _run_isolated_scanner_chain(
        self,
        scanner_id: str,
        dependent_scanner_ids: tuple[str, ...],
        scanner_index: int | None,
        scanner_indexes: dict[str, int],
    ) -> ScannerRunner:
        child = self.child_runner_factory.create_inherited_child_runner(
            parent=self.runner,
            progress=self.dependencies.progress,
            scanner_total=self.dependencies.scanner_total,
        )
        self._run_child_scanner_with_timeout(
            child,
            scanner_id,
            scanner_index=scanner_index,
        )
        if self._scanner_timed_out(child.active_attempt):
            for dependent_id in dependent_scanner_ids:
                self.skip_coordinator.add_dependency_skipped_child_result(
                    child,
                    dependent_id,
                    dependency_id=scanner_id,
                    scanner_index=scanner_indexes.get(dependent_id),
                )
                self._add_result_to_timeout_snapshot(child, child.output_state.results[-1])
            return child
        for dependent_id in dependent_scanner_ids:
            self._run_child_scanner_with_timeout(
                child,
                dependent_id,
                scanner_index=scanner_indexes.get(dependent_id),
            )
        return child

    def _run_child_scanner_with_timeout(
        self,
        child: ScannerRunner,
        scanner_id: str,
        *,
        scanner_index: int | None,
    ) -> ScannerExecutionResult:
        timeout_seconds = self.runner.runtime_state.runtime_config.scanner_timeout_seconds
        attempt = ScannerAttemptContext(
            scanner_id=scanner_id,
            timeout_seconds=timeout_seconds,
        )
        child.context_state.bind_attempt(attempt)
        safe_before = ScannerRunnerOutputSnapshot.capture(child)
        attempt_result = self.attempt_supervisor.run(
            attempt,
            lambda: self.scanner_operation.run_scanner(
                child,
                scanner_id,
                scanner_index=scanner_index,
            ),
        )
        if attempt_result.timed_out:
            extra_limitations = self._build_deadline_limitations(
                child,
                scanner_id,
                attempt_result.error,
            )
            extra_coverage_notes = self._pop_deadline_coverage_notes(
                child,
                scanner_id,
            )
            return self._record_timeout_result(
                child,
                scanner_id,
                scanner_index=scanner_index,
                duration_ms=attempt_result.duration_ms,
                timeout_seconds=timeout_seconds,
                safe_before=safe_before,
                extra_coverage_notes=extra_coverage_notes,
                extra_limitations=extra_limitations,
            )
        if attempt_result.value is not None:
            return attempt_result.value
        if attempt_result.outcome_reason is ScannerAttemptOutcomeReason.UNHANDLED_WORKER_FAILURE:
            runner = self.schedule_helpers.build_scheduler_failure_runner(
                scanner_id,
                RuntimeError(attempt_result.error or "Scanner failed."),
            )
            child.output_state.results.extend(runner.output_state.results)
            return child.output_state.results[-1]
        return self._record_timeout_result(
            child,
            scanner_id,
            scanner_index=scanner_index,
            duration_ms=attempt_result.duration_ms,
            timeout_seconds=timeout_seconds,
            safe_before=safe_before,
        )

    def _record_timeout_result(
        self,
        child: ScannerRunner,
        scanner_id: str,
        *,
        scanner_index: int | None,
        duration_ms: int,
        timeout_seconds: int,
        safe_before: ScannerRunnerOutputSnapshot,
        extra_coverage_notes: list[dict[str, Any]] | None = None,
        extra_limitations: list[str] | None = None,
    ) -> ScannerExecutionResult:
        timeout_result = self.schedule_helpers.build_scanner_timeout_result(
            scanner_id,
            duration_ms=duration_ms,
            timeout_seconds=timeout_seconds,
            extra_coverage_notes=extra_coverage_notes,
            extra_limitations=extra_limitations,
        )
        child.output_state.results.append(timeout_result)
        child.output_state.timeout_merge_snapshot = safe_before.with_result(timeout_result)
        self.schedule_helpers.notify(
            ScanProgressEvent(
                event_type="scanner_completed",
                scanner_id=scanner_id,
                scanner_display_name=get_scanner(scanner_id).display_name,
                scanner_index=scanner_index,
                scanner_total=self.dependencies.scanner_total,
                scanner_status=timeout_result.status,
                findings_count=0,
                message=timeout_result.reason,
            ),
        )
        return timeout_result

    def _scanner_timed_out(self, attempt: ScannerAttemptContext | None) -> bool:
        return attempt is not None and attempt.outcome_reason in {
            ScannerAttemptOutcomeReason.EXPLICIT_CANCELLATION,
            ScannerAttemptOutcomeReason.DEADLINE_EXPIRED,
            ScannerAttemptOutcomeReason.SCHEDULER_TIMEOUT,
        }

    def _add_result_to_timeout_snapshot(
        self,
        child: ScannerRunner,
        result: ScannerExecutionResult,
    ) -> None:
        snapshot = child.output_state.timeout_merge_snapshot
        if snapshot is not None:
            child.output_state.timeout_merge_snapshot = snapshot.with_result(result)

    def _get_merge_visible_results(
        self,
        child: ScannerRunner,
    ) -> list[ScannerExecutionResult]:
        """Return the results that are safe for scheduler accounting."""
        snapshot = child.output_state.timeout_merge_snapshot
        if snapshot is not None:
            return list(snapshot.results)
        return list(child.output_state.results)

    def _pop_deadline_coverage_notes(
        self,
        child: ScannerRunner,
        scanner_id: str,
    ) -> list[dict[str, Any]]:
        """Return deadline notes from a cooperatively stopped scanner."""
        notes = child.note_state.scanner_coverage_notes.pop(scanner_id, [])
        return [note for note in notes if note.get("note_type") == "scanner_deadline_limited_evidence"]

    def _build_deadline_limitations(
        self,
        child: ScannerRunner,
        scanner_id: str,
        error: str | None,
    ) -> list[str]:
        """Build safe timeout limitations from cooperative deadline notes."""
        notes = child.note_state.scanner_coverage_notes.get(scanner_id, [])
        limitations = [
            str(note["summary"]) for note in notes if note.get("note_type") == "scanner_deadline_limited_evidence" and isinstance(note.get("summary"), str)
        ]
        if not limitations and error:
            limitations.append(error)
        return limitations
