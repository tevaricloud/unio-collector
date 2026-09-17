from __future__ import annotations  # noqa: D104

from typing import TYPE_CHECKING, Any

from unio_collector.scan_workflow.runner.state_initialization import (
    ScannerRunnerStateInitializer,
)
from unio_collector.scan_workflow.runner.summaries import ScannerRunSummaryService

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.billing.service_spend import ServiceSpendObservation as ServiceSpendDelta
    from unio_collector.core.cost_period import CostPeriod
    from unio_collector.evidence.collection_store import CollectionEvidenceStore
    from unio_collector.providers.finding_source import FindingSource as Finding
    from unio_collector.scan_workflow.aws.scan.state import AwsScanState
    from unio_collector.scan_workflow.progress import ScanProgressEvent
    from unio_collector.scan_workflow.runner.components import ScannerRuntimeComponents
    from unio_collector.scan_workflow.runner.evidence_gateway import (
        ScannerRunnerEvidenceGateway,
    )
    from unio_collector.scan_workflow.runner.runtime_state import ScannerRuntimeStateView
    from unio_collector.scan_workflow.runner.state import (
        ScannerRunnerContextState,
        ScannerRunnerEvidenceState,
        ScannerRunnerNoteState,
        ScannerRunnerOutputState,
        ScannerRunnerScheduleState,
    )
    from unio_collector.scan_workflow.scanner.attempt.context import ScannerAttemptContext
    from unio_collector.scan_workflow.scanner.runtime.cancellation import (
        ScannerCancellationToken,
    )
    from unio_collector.scanners.scanner.result import ScannerExecutionResult


class ScannerRunner:
    """Owns mutable per-scan scanner state and shared collection services."""

    _components: ScannerRuntimeComponents
    summary_service: ScannerRunSummaryService

    def __init__(  # noqa: D107
        self,
        state: AwsScanState,
        *,
        progress: Callable[[ScanProgressEvent], None] | None = None,
        scanner_total: int | None = None,
    ) -> None:
        self._components = ScannerRunnerStateInitializer().create(
            state,
            progress=progress,
            scanner_total=scanner_total,
        )
        self.summary_service = ScannerRunSummaryService(self)

    @property
    def context_state(self) -> ScannerRunnerContextState:
        """Return grouped scan-context state for runtime collaborators."""
        return self._components.context_state

    @property
    def output_state(self) -> ScannerRunnerOutputState:
        """Return grouped scanner output state."""
        return self._components.output_state

    @property
    def note_state(self) -> ScannerRunnerNoteState:
        """Return grouped scanner warning and coverage-note state."""
        return self._components.note_state

    @property
    def evidence_state(self) -> ScannerRunnerEvidenceState:
        """Return grouped evidence runtime state."""
        return self._components.evidence_state

    @property
    def schedule_state(self) -> ScannerRunnerScheduleState:
        """Return grouped scheduler state."""
        return self._components.schedule_state

    @property
    def runtime_state(self) -> ScannerRuntimeStateView:
        """Return narrow read-only access to scan state."""
        return self.context_state.runtime_state

    @property
    def cancellation_token(self) -> ScannerCancellationToken:
        """Return cooperative scanner cancellation state."""
        if self.context_state.active_attempt is not None:
            return self.context_state.active_attempt.cancellation_token
        return self.context_state.cancellation_token

    @property
    def active_attempt(self) -> ScannerAttemptContext | None:
        """Return the active scanner attempt, when scheduled."""
        return self.context_state.active_attempt

    @property
    def previous_period(self) -> CostPeriod:
        """Return the previous comparison period."""
        return self.context_state.previous_period

    @previous_period.setter
    def previous_period(self, value: CostPeriod) -> None:
        self.context_state.previous_period = value

    @property
    def current_period(self) -> CostPeriod:
        """Return the current scan period."""
        return self.context_state.current_period

    @current_period.setter
    def current_period(self, value: CostPeriod) -> None:
        self.context_state.current_period = value

    @property
    def findings(self) -> list[Finding]:
        """Return mutable findings collected during the scan."""
        return self.output_state.findings

    @findings.setter
    def findings(self, value: list[Finding]) -> None:
        self.output_state.findings = value

    @property
    def results(self) -> list[ScannerExecutionResult]:
        """Return mutable scanner execution results."""
        return self.output_state.results

    @results.setter
    def results(self, value: list[ScannerExecutionResult]) -> None:
        self.output_state.results = value

    @property
    def service_deltas(self) -> list[ServiceSpendDelta]:
        """Return mutable service-spend delta records."""
        return self.output_state.service_deltas

    @service_deltas.setter
    def service_deltas(self, value: list[ServiceSpendDelta]) -> None:
        self.output_state.service_deltas = value

    @property
    def scanner_data(self) -> dict[str, Any]:
        """Return mutable scanner data used in scan summaries."""
        return self.output_state.scanner_data

    @scanner_data.setter
    def scanner_data(self, value: dict[str, Any]) -> None:
        self.output_state.scanner_data = value

    @property
    def evidence_store(self) -> CollectionEvidenceStore:
        """Return collected scanner evidence records."""
        return self.output_state.evidence_store

    @evidence_store.setter
    def evidence_store(self, value: CollectionEvidenceStore) -> None:
        self.output_state.evidence_store = value

    @property
    def evidence_gateway(self) -> ScannerRunnerEvidenceGateway:
        """Return the composite evidence gateway compatibility surface."""
        return self.evidence_state.evidence_gateway

    @evidence_gateway.setter
    def evidence_gateway(self, value: ScannerRunnerEvidenceGateway) -> None:
        self.evidence_state.evidence_gateway = value
