from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.scan_workflow.evidence.runtime_adapter import (
    ScannerEvidenceRuntimeAdapter,
)
from unio_collector.scan_workflow.evidence_collection import (
    ScannerEvidenceCollectionService,
)
from unio_collector.scan_workflow.periods import default_cost_periods
from unio_collector.scan_workflow.runner.components import ScannerRuntimeComponents
from unio_collector.scan_workflow.runner.evidence_gateway import ScannerRunnerEvidenceGateway
from unio_collector.scan_workflow.runner.runtime_state import ScannerRuntimeStateView
from unio_collector.scan_workflow.runner.state import (
    ScannerRunnerContextState,
    ScannerRunnerEvidenceState,
    ScannerRunnerNoteState,
    ScannerRunnerOutputState,
    ScannerRunnerScheduleState,
)
from unio_collector.scan_workflow.service.usage.precheck import (
    ServiceUsagePrecheckPolicy,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.scan_workflow.aws.scan.state import AwsScanState
    from unio_collector.scan_workflow.progress import ScanProgressEvent


class ScannerRunnerStateInitializer:
    """Create mutable scanner-runner state and owned collaborators."""

    def create(
        self,
        state: AwsScanState,
        *,
        progress: Callable[[ScanProgressEvent], None] | None,
        scanner_total: int | None,
    ) -> ScannerRuntimeComponents:
        """Return a complete per-scan state and collaborator graph."""
        previous_period, current_period = default_cost_periods(state.config)
        context_state = ScannerRunnerContextState(
            state=state,
            runtime_state=ScannerRuntimeStateView(state),
            progress=progress,
            scanner_total=scanner_total,
            previous_period=previous_period,
            current_period=current_period,
        )
        output_state = ScannerRunnerOutputState()
        note_state = ScannerRunnerNoteState()
        shared_evidence_prefetches: list[dict[str, Any]] = []
        evidence_runtime = ScannerEvidenceRuntimeAdapter(
            context_state,
            note_state,
            shared_evidence_prefetches,
        )
        collection_service = ScannerEvidenceCollectionService(
            evidence_runtime,
        )
        evidence_gateway = ScannerRunnerEvidenceGateway(
            collection_service,
        )
        evidence_state = ScannerRunnerEvidenceState(
            evidence_runtime=evidence_runtime,
            collection_service=collection_service,
            evidence_gateway=evidence_gateway,
            shared_evidence_prefetches=shared_evidence_prefetches,
        )
        schedule_state = ScannerRunnerScheduleState(
            service_usage_precheck_policy=ServiceUsagePrecheckPolicy(
                enabled=state.config.service_usage_precheck_enabled,
                force_run=state.config.force_service_scanners,
            ),
        )
        return ScannerRuntimeComponents(
            context_state=context_state,
            output_state=output_state,
            note_state=note_state,
            evidence_state=evidence_state,
            schedule_state=schedule_state,
        )
