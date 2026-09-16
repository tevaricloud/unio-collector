from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from unio_collector.billing.service_spend import ServiceSpendObservation as ServiceSpendDelta
    from unio_collector.core.cost_period import CostPeriod
    from unio_collector.evidence.collection_store import CollectionEvidenceStore
    from unio_collector.providers.finding_source import FindingSource as Finding
    from unio_collector.scan_workflow.runner.evidence_gateway import (
        ScannerRunnerEvidenceGateway,
    )
    from unio_collector.scan_workflow.runner.runtime_state import ScannerRuntimeStateView
    from unio_collector.scan_workflow.runner.state import ScannerRunnerOutputState
    from unio_collector.scan_workflow.runner.summaries import ScannerRunSummaryService
    from unio_collector.scanners.scanner.result import ScannerExecutionResult


class AwsScanRunnerContract(Protocol):
    """Runner contract required by AwsScanBuilder helper services."""

    @property
    def runtime_state(self) -> ScannerRuntimeStateView:
        """Return read-only runtime state."""
        ...

    @property
    def findings(self) -> list[Finding]:
        """Return collected findings."""
        ...

    @findings.setter
    def findings(self, value: list[Finding]) -> None:
        """Replace collected findings."""
        ...

    @property
    def results(self) -> list[ScannerExecutionResult]:
        """Return scanner execution results."""
        ...

    @property
    def scanner_data(self) -> dict[str, Any]:
        """Return scanner summary data."""
        ...

    @property
    def output_state(self) -> ScannerRunnerOutputState:
        """Return grouped scanner output state."""
        ...

    @property
    def evidence_gateway(self) -> ScannerRunnerEvidenceGateway:
        """Return the scanner evidence gateway."""
        ...

    @property
    def evidence_store(self) -> CollectionEvidenceStore:
        """Return collected evidence records."""
        ...

    @property
    def summary_service(self) -> ScannerRunSummaryService:
        """Return the scanner run summary service."""
        ...

    @property
    def previous_period(self) -> CostPeriod:
        """Return the previous comparison period."""
        ...

    @property
    def current_period(self) -> CostPeriod:
        """Return the current scan period."""
        ...

    @property
    def service_deltas(self) -> list[ServiceSpendDelta]:
        """Return service spend deltas."""
        ...
