from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime


@dataclass
class CollectorExecutionResult:
    """Provider-neutral output from collection-only execution."""

    provider_id: str
    generated_at: datetime
    account_context: dict[str, Any]
    scan_period: object
    scanner_results: list[Any]
    ledger: object
    evidence_store: object
    config: object | None = None
    api_telemetry: dict[str, Any] = field(default_factory=dict)
    scanner_evidence_payloads: list[dict[str, Any]] = field(default_factory=list)
    pricing_context: dict[str, Any] | None = None
    collection_summary: dict[str, Any] = field(default_factory=dict)
    limitations: list[dict[str, Any]] = field(default_factory=list)
    collection_status: str = "complete"

    def __post_init__(self) -> None:
        """Derive an explicit collection status from scanner outcomes."""
        from unio_collector.collector.analysis.coverage import (  # noqa: PLC0415
            ScannerEvidenceCoverage,
        )

        coverage = ScannerEvidenceCoverage.assess(
            scanner_results=[result.convert_to_dict() if callable(getattr(result, "convert_to_dict", None)) else result for result in self.scanner_results],
            scanner_evidence_payloads=self.scanner_evidence_payloads,
            provider_id=self.provider_id,
        )
        self.collection_status = coverage.collection_status
        self.collection_summary["scanner_evidence_coverage"] = coverage.convert_to_dict()
        self.collection_summary["collection_status"] = self.collection_status
