"""Execute the registered commitment collector and canonical callback serialization."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

from tools.collector_commitment.session import SyntheticCommitmentSession
from tools.collector_sdk_fixture import SyntheticWrapperRuntime
from unio_collector.core.scan.period_resolver import ScanPeriodResolver
from unio_collector.scanners.cost_explorer.commitment.collection import CommitmentAndPricingReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload
from unio_collector.scanners.scanner.result import ScannerExecutionResult

SCANNER = "commitment-and-pricing-review"
VARIANTS = (
    "success",
    "empty",
    "nullable",
    "partial",
    "denied",
    "unavailable",
    "unsupported",
    "failure",
    "malformed_numeric",
    "cross_account",
    "collision",
    "dimension_collision",
    "financial_collision",
    "groups",
    "unknown_dimension",
)


def commitment_producer_observation(variant: str = "success") -> dict[str, Any]:
    """Collect actual inventory/metrics and serialize through their canonical public contract."""
    if variant not in VARIANTS:
        message = "Unknown synthetic commitment case"
        raise ValueError(message)
    session = SyntheticCommitmentSession(variant)
    runtime = SyntheticWrapperRuntime(
        session, options={}, service_costs=[], daily_costs=[], scan_period=ScanPeriodResolver().resolve(date_from="2026-01-01", date_to="2026-01-31")
    )
    definition: Any = SimpleNamespace(scanner_id=SCANNER, display_name=SCANNER)
    evidence = CommitmentAndPricingReviewCollector(definition).collect(ScannerContext(runtime=cast("Any", runtime), definition=definition))
    execution = ScannerExecutionResult(
        scanner_id=SCANNER,
        status="completed",
        warnings=runtime.warnings,
        coverage_notes=runtime.notes,
        regions_scanned=list(evidence.portfolio.regions) if evidence.portfolio is not None else [],
    ).convert_to_dict()
    return {
        "evidence": build_scanner_evidence_payload(scanner_id=SCANNER, evidence=evidence),
        "execution": execution,
        "callbacks": runtime.callbacks,
        "operations": session.calls,
    }
