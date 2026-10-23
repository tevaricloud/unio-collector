"""Actual flow-log attribution through SDK discovery, queries and topology enrichment."""

from __future__ import annotations

from datetime import date
from types import SimpleNamespace
from typing import Any

from tools.collector_attribution.session import SyntheticAttributionSession
from tools.collector_sdk_fixture import SyntheticWrapperRuntime
from unio_collector.core.scan.period_resolver import ScanPeriodResolver
from unio_collector.scanners.network.vpc_flow.attribution.collector import VpcFlowLogAttributionCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload
from unio_collector.scanners.scanner.result import ScannerExecutionResult

SCANNER = "vpc-flow-log-attribution"
VARIANTS = (
    "success",
    "empty",
    "nullable",
    "partial",
    "denied",
    "unavailable",
    "unsupported",
    "failure",
    "format",
    "destination",
    "query_failure",
    "collision",
    "numeric_collision",
    "query_denied",
    "route_denied",
    "ambiguous",
    "ipv6",
    "public",
    "cap",
    "definitions_cap",
    "days",
    "months",
    "years",
)


def flow_producer_observation(variant: str = "success") -> dict[str, Any]:
    """Invoke the real registered wrapper, all actual collection stages and serialization."""
    if variant not in VARIANTS:
        message = "Unknown synthetic flow case"
        raise ValueError(message)
    session = SyntheticAttributionSession(variant)
    period = (
        ScanPeriodResolver().resolve(
            days=1 if variant == "days" else None,
            months=1 if variant == "months" else None,
            years=1 if variant == "years" else None,
            reference_date=date(2026, 2, 1),
        )
        if variant in {"days", "months", "years"}
        else ScanPeriodResolver().resolve(date_from="2026-01-01", date_to="2026-01-31")
    )
    options: dict[str, object] = {"query_limit": 1} if variant == "cap" else {"max_log_groups_per_region": 1} if variant == "definitions_cap" else {}
    runtime: Any = SyntheticWrapperRuntime(session, options=options, service_costs=[], daily_costs=[], scan_period=period)
    definition: Any = SimpleNamespace(scanner_id=SCANNER, display_name=SCANNER)
    evidence = VpcFlowLogAttributionCollector(definition).collect(ScannerContext(runtime=runtime, definition=definition))
    return {
        "evidence": build_scanner_evidence_payload(scanner_id=SCANNER, evidence=evidence),
        "execution": ScannerExecutionResult(
            scanner_id=SCANNER, status="completed", warnings=runtime.warnings, coverage_notes=runtime.notes, regions_scanned=evidence.regions
        ).convert_to_dict(),
        "callbacks": runtime.callbacks,
        "operations": session.calls,
    }
