from __future__ import annotations  # noqa: D100

from copy import deepcopy
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.billing.service_spend import ServiceSpendObservation as ServiceSpendDelta
    from unio_collector.evidence.models import EvidenceRecord
    from unio_collector.providers.finding_source import FindingSource as Finding
    from unio_collector.scan_workflow.runner.merge_contract import (
        ScannerChildMergeRuntimeContract,
    )
    from unio_collector.scanners.scanner.result import ScannerExecutionResult


@dataclass(frozen=True)
class ScannerRunnerOutputSnapshot:
    """Immutable merge source captured before abandoning a scanner thread."""

    findings: list[Finding]
    results: list[ScannerExecutionResult]
    service_deltas: list[ServiceSpendDelta]
    scanner_data: dict[str, Any]
    scanner_evidence_payloads: list[dict[str, Any]]
    scanner_warnings: dict[str, list[str]]
    scanner_coverage_notes: dict[str, list[dict[str, Any]]]
    evidence_records: list[EvidenceRecord]
    inherited_service_delta_count: int

    @classmethod
    def capture(
        cls,
        runner: ScannerChildMergeRuntimeContract,
    ) -> ScannerRunnerOutputSnapshot:
        """Capture scanner output that is safe to merge into the parent."""
        output_state = runner.output_state
        note_state = runner.note_state
        return cls(
            findings=list(output_state.findings),
            results=list(output_state.results),
            service_deltas=list(output_state.service_deltas),
            scanner_data=deepcopy(output_state.scanner_data),
            scanner_evidence_payloads=deepcopy(output_state.scanner_evidence_payloads),
            scanner_warnings=deepcopy(note_state.scanner_warnings),
            scanner_coverage_notes=deepcopy(note_state.scanner_coverage_notes),
            evidence_records=list(output_state.evidence_store.get_records()),
            inherited_service_delta_count=output_state.inherited_service_delta_count,
        )

    def with_result(
        self,
        result: ScannerExecutionResult,
    ) -> ScannerRunnerOutputSnapshot:
        """Return a copy with one scheduler-owned result appended."""
        return replace(self, results=[*self.results, result])
