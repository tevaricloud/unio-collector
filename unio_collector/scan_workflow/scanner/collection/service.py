from __future__ import annotations  # noqa: D100

from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from unio_collector.aws.audit import is_permission_error
from unio_collector.runtime_diagnostics.exception_record import sanitize_diagnostic_text
from unio_collector.scan_workflow.progress import ScanProgressEvent
from unio_collector.scan_workflow.scanner.diagnostics import ScannerCollectionDiagnostics
from unio_collector.scan_workflow.scanner.result_builder import (
    ScannerScheduleResultBuilder,
)
from unio_collector.scan_workflow.scanner.runtime.adapter import ScannerRuntimeAdapter
from unio_collector.scan_workflow.scanner.runtime.cancellation_error import (
    ScannerDeadlineExceededError,
)
from unio_collector.scanners.registry.catalog import get_scanner
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import (
    build_scanner_evidence_payload,
    require_serialized_scanner_evidence,
)
from unio_collector.scanners.scanner.reference_time import AnalysisReferenceTime

if TYPE_CHECKING:
    from unio_collector.scan_workflow.scanner.runtime.dependencies import (
        ScannerRuntimeDependencies,
    )
    from unio_collector.scan_workflow.scanner.runtime.execution_contract import (
        ScannerExecutionRuntimeContract,
    )
    from unio_collector.scanners.scanner.collection_protocol import CollectorScannerProtocol
    from unio_collector.scanners.scanner.result import ScannerExecutionResult


class ScannerCollectionService:
    """Run scanner collection without calling scanner analysis."""

    def __init__(self, dependencies: ScannerRuntimeDependencies[CollectorScannerProtocol]) -> None:  # noqa: D107
        self.dependencies = dependencies

    def run_scanner(
        self,
        runner: ScannerExecutionRuntimeContract,
        scanner_id: str,
        *,
        scanner_index: int | None = None,
    ) -> ScannerExecutionResult:
        """Scheduler-compatible alias for collection-only execution."""
        return self.collect_scanner(
            runner,
            scanner_id,
            scanner_index=scanner_index,
        )

    def collect_scanner(
        self,
        runner: ScannerExecutionRuntimeContract,
        scanner_id: str,
        *,
        scanner_index: int | None = None,
    ) -> ScannerExecutionResult:
        """Collect and serialize one scanner's evidence with failure isolation."""
        definition = get_scanner(scanner_id)
        self._notify(
            ScanProgressEvent(
                event_type="scanner_started",
                scanner_id=scanner_id,
                scanner_display_name=definition.display_name,
                scanner_index=scanner_index,
                scanner_total=self.dependencies.scanner_total,
            ),
        )
        started_at = datetime.now(UTC)
        runtime_state = runner.runtime_state
        note_state = runner.note_state
        diagnostics = ScannerCollectionDiagnostics(runtime_state)
        diagnostic_count = diagnostics.get_collection_diagnostics_count()
        errors: list[str] = []
        regions: list[str] = []
        status = "completed"
        implementation = None
        evidence: object | None = None
        evidence_recorded = False
        try:
            collector_scanner = cast(
                "CollectorScannerProtocol",
                self.dependencies.scanner_factory(scanner_id, definition),
            )
            implementation = collector_scanner.describe_implementation()
            context = ScannerContext(
                runtime=ScannerRuntimeAdapter(
                    runner,
                    analysis_reference_time=AnalysisReferenceTime(
                        started_at,
                        "scanner_started_at",
                    ),
                ),
                definition=definition,
            )
            context.raise_if_cancelled()
            collector_scanner.prepare(context)
            context.raise_if_cancelled()
            evidence = collector_scanner.collect(context)
            context.raise_if_cancelled()
            payload = build_scanner_evidence_payload(scanner_id=scanner_id, evidence=evidence)
            require_serialized_scanner_evidence(payload)
            context.record_scanner_evidence_payload(scanner_id, payload)
            evidence_recorded = True
            regions = self._get_regions(evidence)
        except ScannerDeadlineExceededError:
            raise
        except Exception as exc:  # noqa: BLE001
            errors.append(sanitize_diagnostic_text(exc))
            status = "permission_denied" if is_permission_error(exc) else "failed"
        if runner.active_attempt is not None:
            runner.active_attempt.require_commit_authority()
        else:
            runner.cancellation_token.raise_if_cancelled()
        warnings = note_state.scanner_warnings.pop(scanner_id, [])
        warnings.extend(
            diagnostics.build_collection_warning_messages(
                scanner_id,
                diagnostic_count,
            ),
        )
        if status == "completed" and warnings:
            status = "completed_with_warnings"
        completed_at = datetime.now(UTC)
        result = ScannerScheduleResultBuilder().build_collected_result(
            scanner_id=scanner_id,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            regions_scanned=regions,
            errors=errors,
            warnings=warnings,
            api_calls_attempted=runtime_state.ledger.get_calls_for_scanner(
                scanner_id,
                attempt_id=(runner.active_attempt.attempt_id if runner.active_attempt is not None else None),
            ),
            limitations=[*errors, *definition.limitations],
            coverage_notes=note_state.scanner_coverage_notes.pop(scanner_id, []),
            evidence_count=1 if evidence_recorded and evidence is not None else 0,
            api_call_count=runtime_state.ledger.get_call_count_for_scanner(
                scanner_id,
                attempt_id=(runner.active_attempt.attempt_id if runner.active_attempt is not None else None),
            ),
            implementation=implementation,
        )
        if runner.active_attempt is not None:
            runner.active_attempt.require_commit_authority()
        runner.output_state.results.append(result)
        self._notify(
            ScanProgressEvent(
                event_type="scanner_completed",
                scanner_id=scanner_id,
                scanner_display_name=definition.display_name,
                scanner_index=scanner_index,
                scanner_total=self.dependencies.scanner_total,
                scanner_status=result.status,
                findings_count=0,
                warning_count=len(warnings),
                error_count=len(errors),
                message="; ".join([*errors, *warnings]),
            ),
        )
        return result

    def _get_regions(self, evidence: object) -> list[str]:
        for attribute in ("regions_scanned", "regions", "selected_regions"):
            value = getattr(evidence, attribute, None)
            if isinstance(value, list | tuple):
                return [str(region) for region in value]
        return []

    def _notify(self, event: ScanProgressEvent) -> None:
        if self.dependencies.progress:
            self.dependencies.progress(event)
