from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from unio_collector.evidence.collection_store import CollectionEvidenceStore

if TYPE_CHECKING:
    from collections.abc import Iterable

    from unio_collector.billing.service_spend import ServiceSpendObservation as ServiceSpendDelta
    from unio_collector.providers.finding_source import FindingSource as Finding
    from unio_collector.scan_workflow.runner.snapshot import ScannerRunnerOutputSnapshot
    from unio_collector.scanners.scanner.result import ScannerExecutionResult


@dataclass
class ScannerRunnerOutputState:
    """Mutable scanner outputs accumulated during one scan run."""

    findings: list[Finding] = field(default_factory=list)
    results: list[ScannerExecutionResult] = field(default_factory=list)
    service_deltas: list[ServiceSpendDelta] = field(default_factory=list)
    scanner_data: dict[str, Any] = field(default_factory=dict)
    scanner_evidence_payloads: list[dict[str, Any]] = field(default_factory=list)
    evidence_store: CollectionEvidenceStore = field(default_factory=CollectionEvidenceStore)
    inherited_service_delta_count: int = 0
    timeout_merge_snapshot: ScannerRunnerOutputSnapshot | None = None

    def inherit_service_deltas(
        self,
        service_deltas: Iterable[ServiceSpendDelta],
    ) -> None:
        """Copy inherited deltas and record the merge exclusion boundary."""
        self.service_deltas = list(service_deltas)
        self.inherited_service_delta_count = len(self.service_deltas)
