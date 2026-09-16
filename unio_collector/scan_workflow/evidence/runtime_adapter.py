from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.scan_workflow.aws.collector_factory import ScannerAwsCollectorFactory
from unio_collector.scan_workflow.evidence.runtime import ScannerEvidenceRuntime
from unio_collector.scan_workflow.scanner.note_recorder import ScannerRunNoteRecorder

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.cost_explorer import CostExplorerCollector
    from unio_collector.scan_workflow.evidence.adapter_target import (
        ScannerEvidenceRuntimeAdapterTarget,
    )
    from unio_collector.scan_workflow.runner.runtime_state import ScannerRuntimeStateView
    from unio_collector.scan_workflow.runner.state import ScannerRunnerNoteState
    from unio_collector.scan_workflow.scanner.attempt.context import ScannerAttemptContext
    from unio_collector.scan_workflow.scanner.runtime.cancellation import (
        ScannerCancellationToken,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class ScannerEvidenceRuntimeAdapter(ScannerEvidenceRuntime):
    """Expose only evidence-runtime needs from the mutable scanner runner."""

    def __init__(
        self,
        context: ScannerEvidenceRuntimeAdapterTarget,
        note_state: ScannerRunnerNoteState,
        shared_evidence_prefetches: list[dict[str, Any]],
    ) -> None:
        """Bind the focused context and mutable evidence-owned stores."""
        self._context = context
        self.note_state = note_state
        self._shared_evidence_prefetches = shared_evidence_prefetches

    @property
    def runtime_state(self) -> ScannerRuntimeStateView:
        """Return read-only runtime state used by evidence collaborators."""
        return self._context.runtime_state

    @property
    def shared_evidence_prefetches(self) -> list[dict[str, Any]]:
        """Return mutable prefetch records used by evidence-prefetch helpers."""
        return self._shared_evidence_prefetches

    @property
    def cancellation_token(self) -> ScannerCancellationToken:
        """Return the active scanner cancellation token."""
        if self._context.active_attempt is not None:
            return self._context.active_attempt.cancellation_token
        return self._context.cancellation_token

    @property
    def active_attempt(self) -> ScannerAttemptContext | None:
        """Return the active scanner attempt context."""
        return self._context.active_attempt

    def create_audit_context(
        self,
        definition: ScannerDefinition,
        collector: str,
    ) -> AwsAuditContext:
        """Create an audited AWS context for shared evidence collection."""
        return ScannerAwsCollectorFactory(
            self.runtime_state,
            attempt=self.active_attempt,
        ).create_audit_context(
            definition,
            collector,
        )

    def create_cost_explorer_collector(
        self,
        audit_context: AwsAuditContext,
    ) -> CostExplorerCollector:
        """Create a Cost Explorer collector for shared cached evidence calls."""
        return ScannerAwsCollectorFactory(
            self.runtime_state,
        ).create_cost_explorer_collector(audit_context)

    def add_scanner_coverage_note(
        self,
        scanner_id: str,
        note: dict[str, Any],
    ) -> None:
        """Record a scanner coverage note from evidence cache access."""
        ScannerRunNoteRecorder(self).add_scanner_coverage_note(
            scanner_id,
            note,
        )
