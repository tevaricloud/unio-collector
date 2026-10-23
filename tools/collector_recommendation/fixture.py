"""Actual recommendation collectors, framework callbacks and wire serialization."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

from tools.collector_recommendation.response import VARIANTS
from tools.collector_recommendation.session import SyntheticRecommendationSession
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.api.call_ledger import ApiCallLedger
from unio_collector.scan_workflow.scanner.collection.service import ScannerCollectionService
from unio_collector.scan_workflow.scanner.runtime.cancellation import ScannerCancellationToken
from unio_collector.scan_workflow.scanner.runtime.dependencies import ScannerRuntimeDependencies
from unio_collector.scanners.aws_native.compute_optimizer.collector import ComputeOptimizerRecommendationReviewCollector
from unio_collector.scanners.aws_native.cost_hub.collector import CostOptimizationHubRecommendationReviewCollector

COLLECTORS = {
    "compute-optimizer-recommendation-review": (ComputeOptimizerRecommendationReviewCollector, "compute-optimizer"),
    "cost-optimization-hub-recommendation-review": (CostOptimizationHubRecommendationReviewCollector, "cost-optimization-hub"),
}

CASE_VARIANTS = {
    scanner: tuple(v for v in VARIANTS if v != "metric_collision" or scanner == "compute-optimizer-recommendation-review") for scanner in COLLECTORS
}


def recommendation_producer_observation(scanner: str, variant: str = "success") -> dict[str, Any]:
    """Drive the actual framework collector, callbacks and canonical serializer."""
    if scanner not in CASE_VARIANTS or variant not in CASE_VARIANTS[scanner]:
        message = "Unsupported synthetic recommendation variant"
        raise ValueError(message)
    wrapper, service = COLLECTORS[scanner]
    session = SyntheticRecommendationSession(service, variant)
    events = []
    state = SimpleNamespace(
        account_id="123456789012",
        session=session,
        config=SimpleNamespace(),
        collection_diagnostics=None,
        ledger=ApiCallLedger(),
        get_selected_regions=lambda: [] if variant == "missing_scope" else ["eu-west-2"],
        has_explicit_region_scope=lambda: variant != "missing_scope",
        get_scanner_option=lambda _s, _k, d: d,
    )
    runner = SimpleNamespace(
        runtime_state=state,
        note_state=SimpleNamespace(scanner_warnings={}, scanner_coverage_notes={}),
        output_state=SimpleNamespace(scanner_evidence_payloads=[], results=[], scanner_data={}),
        active_attempt=None,
        cancellation_token=ScannerCancellationToken(),
        evidence_gateway=SimpleNamespace(get_cached_ec2_regions=lambda _d: []),
    )
    deps = ScannerRuntimeDependencies(scanner_factory=lambda _id, d: wrapper(d), progress=events.append, scanner_total=1)
    execution = ScannerCollectionService(deps).collect_scanner(cast("Any", runner), scanner)
    return {
        "evidence": runner.output_state.scanner_evidence_payloads[0] if runner.output_state.scanner_evidence_payloads else None,
        "execution": execution.convert_to_dict(),
        "operations": session.calls,
        "events": [
            {
                "event_type": e.event_type,
                "scanner_status": e.scanner_status,
                "warning_count": e.warning_count,
                "error_count": e.error_count,
                "message": e.message,
            }
            for e in events
        ],
    }


def add_recommendation_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Add actual full provider shapes with their real callback execution records."""
    for scanner in COLLECTORS:
        observed = recommendation_producer_observation(scanner)
        if unknown:
            observed["evidence"]["payload"]["records"][0]["recommended_configuration"]["unknown_recommendation_control"] = None
        add_scanner_producer_payload(files, observed["evidence"], execution=observed["execution"])
