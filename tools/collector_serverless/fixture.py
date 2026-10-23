"""Actual related wrapper invocations, callbacks and canonical serialization."""

from __future__ import annotations

from datetime import date
from typing import Any

from botocore.exceptions import ClientError

from tools.collector_sdk_fixture import add_wrapper_observation
from tools.collector_serverless.runtime import SyntheticServerlessRuntime
from tools.collector_serverless.session import SyntheticServerlessSession
from unio_collector.core.scan.period import ScanPeriod
from unio_collector.scanners.collection.lambda_cycle import LambdaCostCycleRiskCollector
from unio_collector.scanners.collection.serverless_polling import SqsLambdaPollingCostReviewCollector
from unio_collector.scanners.lifecycle.collector import ExtendedSupportAndEolReviewCollector
from unio_collector.scanners.registry.catalog import get_scanner
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload
from unio_collector.scanners.scanner.result import ScannerExecutionResult

LAMBDA = "lambda-cost-cycle-risk-review"
POLLING = "sqs-lambda-polling-cost-review"
LIFECYCLE = "extended-support-and-eol-review"
COLLECTORS = {LAMBDA: LambdaCostCycleRiskCollector, POLLING: SqsLambdaPollingCostReviewCollector, LIFECYCLE: ExtendedSupportAndEolReviewCollector}
COMMON = ("success", "empty", "denied", "unsupported", "failure", "unavailable", "partial", "nullable")
VARIANTS = {
    LAMBDA: (
        *COMMON,
        "summary",
        "capped",
        "tag_denied",
        "url_environment",
        "case_environment",
        "unrelated_environment",
        "invoke_unavailable",
        "environment_tags",
        "native",
    ),
    POLLING: (*COMMON, "capped", "no_data"),
    LIFECYCLE: (*COMMON, "image_unavailable", "tag_denied", "environment_tags", "native"),
}


def serverless_producer_observation(scanner: str, variant: str = "success") -> dict[str, Any]:
    """Run the registered wrapper and actual shared providers using synthetic SDK data."""
    session = SyntheticServerlessSession(variant)
    period = ScanPeriod(
        kind="days",
        raw_input={"days": 30},
        current_start_date=date(2026, 9, 1),
        current_end_date=date(2026, 9, 30),
        previous_start_date=date(2026, 8, 2),
        previous_end_date=date(2026, 8, 31),
    )
    options: dict[str, object] = {"s3_notification_worker_count": 1, "s3_policy_scan_max_functions": 2}
    if variant == "summary":
        options["s3_notification_detail_mode"] = "summary"
    if variant == "capped":
        options.update(max_s3_buckets=1, max_mappings_per_region=1)
    runtime: Any = SyntheticServerlessRuntime(session, options=options, period=period)
    definition = get_scanner(scanner)
    wrapper = COLLECTORS[scanner](definition)
    try:
        evidence = wrapper.collect(ScannerContext(runtime=runtime, definition=definition))
    except ClientError as exc:
        if (scanner, variant) != (LAMBDA, "unavailable"):
            raise
        return {
            "collection_exception": {"type": type(exc).__name__, "code": exc.response["Error"]["Code"]},
            "callbacks": runtime.callbacks,
            "provider_calls": session.calls,
            "statuses": [result.status for result in session.collection_diagnostics.get_results_since(0)],
            "diagnostic_warnings": session.collection_diagnostics.build_warning_messages_since(0),
        }
    row = build_scanner_evidence_payload(scanner_id=scanner, evidence=evidence)
    implementation = wrapper.describe_implementation()
    execution = ScannerExecutionResult(
        scanner_id=scanner,
        status="completed_with_warnings" if runtime.warnings else "completed",
        warnings=runtime.warnings,
        coverage_notes=runtime.notes,
        regions_scanned=evidence.regions,
        implementation_type=implementation.implementation_type,
        implementation_class=implementation.implementation_class,
        implementation_module=implementation.implementation_module,
    ).convert_to_dict()
    return {
        "evidence": row,
        "execution": execution,
        "callbacks": runtime.callbacks,
        "provider_calls": session.calls,
        "statuses": [result.status for result in session.collection_diagnostics.get_results_since(0)],
        "diagnostic_warnings": session.collection_diagnostics.build_warning_messages_since(0),
    }


def add_serverless_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Put the same actual full producer and conditional cap envelope in packaged smoke."""
    for scanner in COLLECTORS:
        observed = serverless_producer_observation(scanner, "native" if scanner in {LAMBDA, LIFECYCLE} else "success")
        if scanner == POLLING:
            observed["execution"]["coverage_notes"].extend(serverless_producer_observation(scanner, "capped")["execution"]["coverage_notes"])
        if unknown:
            observed["evidence"]["payload"]["records"][0]["unknown_serverless_control"] = None
        add_wrapper_observation(files, observed)
