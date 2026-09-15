from __future__ import annotations  # noqa: D100

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from unio_collector.aws.audit import is_permission_error
from unio_collector.runtime_diagnostics.exception_record import sanitize_diagnostic_text
from unio_collector.scanners.registry.catalog import get_scanner
from unio_collector.scanners.scanner.result import ScannerExecutionResult

if TYPE_CHECKING:
    from collections.abc import Sequence

    from unio_collector.scan_workflow.service.usage.precheck import (
        ServiceUsagePrecheckDecision,
    )


class ScannerScheduleResultBuilder:
    """Build scheduler-owned scanner execution results."""

    def build_dependency_skipped_result(
        self,
        scanner_id: str,
        *,
        dependency_id: str,
    ) -> ScannerExecutionResult:
        """Build a skipped result for a scanner whose dependency did not run."""
        definition = get_scanner(scanner_id)
        now = datetime.now(UTC)
        reason = f"Skipped because dependency scanner {dependency_id} did not run."
        return ScannerExecutionResult(
            scanner_id=scanner_id,
            status="skipped",
            started_at=now,
            completed_at=now,
            findings_count=0,
            required_iam_actions=list(definition.required_iam_actions),
            conditional_iam_actions=list(definition.conditional_iam_actions),
            required_permission_level=definition.required_permission_level,
            aws_api_calls=list(definition.aws_api_calls),
            limitations=[reason, *definition.limitations],
            coverage_notes=[
                {
                    "note_type": "dependency_skipped",
                    "summary": reason,
                    "dependency_scanner_id": dependency_id,
                    "result_scope": "current_scan",
                    "impact": ("The dependent scanner was not executed because its required upstream evidence was not collected."),
                },
            ],
            reason=reason,
            skip_reason=reason,
            duration_ms=0,
            implementation_type="not_run",
        )

    def build_collected_result(
        self,
        *,
        scanner_id: str,
        status: Any,  # noqa: ANN401
        started_at: datetime,
        completed_at: datetime,
        regions_scanned: list[str],
        errors: list[str],
        warnings: list[str],
        limitations: list[str],
        coverage_notes: list[dict[str, Any]],
        api_calls_attempted: list[str],
        evidence_count: int,
        api_call_count: int,
        implementation: Any,  # noqa: ANN401
    ) -> ScannerExecutionResult:
        """Build a finding-free result for collection-only execution."""
        definition = get_scanner(scanner_id)
        return ScannerExecutionResult(
            scanner_id=scanner_id,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            regions_scanned=regions_scanned,
            findings_count=0,
            errors=errors,
            warnings=warnings,
            required_iam_actions=list(definition.required_iam_actions),
            conditional_iam_actions=list(definition.conditional_iam_actions),
            required_permission_level=definition.required_permission_level,
            aws_api_calls=list(definition.aws_api_calls),
            api_calls_attempted=api_calls_attempted,
            limitations=limitations,
            coverage_notes=coverage_notes,
            duration_ms=int((completed_at - started_at).total_seconds() * 1000),
            evidence_count=evidence_count,
            api_call_count=api_call_count,
            implementation_type=(implementation.implementation_type if implementation else None),
            implementation_class=(implementation.implementation_class if implementation else None),
            implementation_module=(implementation.implementation_module if implementation else None),
        )

    def build_scanner_timeout_result(
        self,
        scanner_id: str,
        *,
        duration_ms: int,
        timeout_seconds: int,
        extra_coverage_notes: Sequence[dict[str, Any]] | None = None,
        extra_limitations: Sequence[str] | None = None,
    ) -> ScannerExecutionResult:
        """Build a failed result for a scanner that exceeded its timeout."""
        definition = get_scanner(scanner_id)
        now = datetime.now(UTC)
        reason = f"Scanner exceeded configured scanner timeout of {timeout_seconds} seconds."
        coverage_notes = [
            {
                "note_type": "scanner_timeout",
                "summary": reason,
                "result_scope": "current_scan",
                "timeout_seconds": timeout_seconds,
                "impact": ("Findings from this scanner are incomplete because it did not finish within the configured timeout."),
            },
            *list(extra_coverage_notes or ()),
        ]
        return ScannerExecutionResult(
            scanner_id=scanner_id,
            status="failed",
            started_at=now,
            completed_at=now,
            findings_count=0,
            errors=[reason],
            warnings=[],
            required_iam_actions=list(definition.required_iam_actions),
            conditional_iam_actions=list(definition.conditional_iam_actions),
            required_permission_level=definition.required_permission_level,
            aws_api_calls=list(definition.aws_api_calls),
            limitations=[
                reason,
                (
                    "The scanner was abandoned to keep the overall scan moving; "
                    "rerun with a higher runtime.scanner_timeout_seconds value "
                    "or reduce scanner detail if full coverage is required."
                ),
                *list(extra_limitations or ()),
                *definition.limitations,
            ],
            coverage_notes=coverage_notes,
            reason=reason,
            duration_ms=duration_ms,
            api_call_count=0,
            implementation_type="timed_out",
        )

    def build_scheduler_failure_result(
        self,
        scanner_id: str,
        exc: Exception,
    ) -> ScannerExecutionResult:
        """Build a failed or permission-denied result for scheduler failures."""
        definition = get_scanner(scanner_id)
        now = datetime.now(UTC)
        status = "permission_denied" if is_permission_error(exc) else "failed"
        return ScannerExecutionResult(
            scanner_id=scanner_id,
            status=status,
            started_at=now,
            completed_at=now,
            errors=[sanitize_diagnostic_text(exc)],
            required_iam_actions=list(definition.required_iam_actions),
            conditional_iam_actions=list(definition.conditional_iam_actions),
            required_permission_level=definition.required_permission_level,
            aws_api_calls=list(definition.aws_api_calls),
            limitations=list(definition.limitations),
            duration_ms=0,
            implementation_type="unavailable",
        )

    def build_service_precheck_skipped_result(
        self,
        scanner_id: str,
        decision: ServiceUsagePrecheckDecision,
    ) -> ScannerExecutionResult:
        """Build a skipped result from a service-usage precheck decision."""
        definition = get_scanner(scanner_id)
        now = datetime.now(UTC)
        return ScannerExecutionResult(
            scanner_id=scanner_id,
            status="skipped",
            started_at=now,
            completed_at=now,
            findings_count=0,
            required_iam_actions=list(definition.required_iam_actions),
            conditional_iam_actions=list(definition.conditional_iam_actions),
            required_permission_level=definition.required_permission_level,
            aws_api_calls=list(definition.aws_api_calls),
            limitations=list(definition.limitations),
            coverage_notes=[decision.convert_to_coverage_note()],
            reason=decision.reason,
            skip_reason=decision.reason,
            duration_ms=0,
            implementation_type="not_run",
        )
