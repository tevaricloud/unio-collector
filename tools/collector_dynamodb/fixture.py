"""Actual registered DynamoDB collection, callbacks and canonical serialization."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Any

from tools.collector_dynamodb.session import SyntheticDynamoSession
from tools.collector_sdk_fixture import SyntheticWrapperRuntime, add_wrapper_observation
from unio_collector.aws.cost_explorer.result import CostExplorerResult
from unio_collector.aws.daily_cost_record import DailyCostRecord
from unio_collector.core.cost_period import CostPeriod
from unio_collector.core.scan.period import ScanPeriod
from unio_collector.scanners.dynamodb.cost_governance.collector import DynamoDbCostGovernanceReviewCollector
from unio_collector.scanners.registry.catalog import get_scanner
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload
from unio_collector.scanners.scanner.result import ScannerExecutionResult

SCANNER = "dynamodb-cost-governance-review"
VARIANTS = (
    "success",
    "empty",
    "denied",
    "unsupported",
    "failure",
    "unavailable",
    "partial",
    "nullable",
    "malformed",
    "summary",
    "billing_active",
    "no_cost",
    "retention_denied",
    "tags_denied",
    "autoscaling_denied",
    "metrics_partial",
    "literal_collision",
)


def dynamodb_producer_observation(variant: str = "success") -> dict[str, Any]:
    """Use populated SDK providers and real branch policies; preserve limitation shapes."""
    session = SyntheticDynamoSession(variant)
    options: dict[str, object] = {"max_table_workers": 1}
    if variant == "summary":
        options.update(retention_detail_mode="summary", metric_detail_mode="summary", autoscaling_detail_mode="summary")
    if variant == "billing_active":
        options["table_detail_regional_mode"] = "billing-active"
    period = ScanPeriod(
        kind="months",
        raw_input={"months": 1},
        current_start_date=date(2026, 9, 1),
        current_end_date=date(2026, 9, 30),
        previous_start_date=date(2026, 8, 1),
        previous_end_date=date(2026, 8, 31),
    )
    costs = (
        None
        if variant in {"no_cost", "nullable"}
        else CostExplorerResult(
            previous_period=CostPeriod(start_date=date(2026, 8, 1), end_date=date(2026, 8, 31), total_cost=Decimal("9.50"), currency="USD"),
            current_period=CostPeriod(start_date=date(2026, 9, 1), end_date=date(2026, 9, 30), total_cost=Decimal("17.25"), currency="USD"),
            service_costs=[{"service_name": "Amazon DynamoDB", "current_cost": "17.25", "previous_cost": "9.50", "currency": "USD"}],
        )
    )
    daily = [DailyCostRecord(date=date(2026, 9, 1), service_name="Amazon DynamoDB", region="eu-west-2", usage_type=None, cost=Decimal("17.25"), currency="USD")]
    runtime: Any = SyntheticWrapperRuntime(
        session,
        options=options,
        service_costs=costs,
        daily_costs=daily,
        scan_period=period,
        selected_regions=("eu-west-2", "eu-central-1") if variant == "billing_active" else ("eu-west-2",),
    )
    definition = get_scanner(SCANNER)
    wrapper = DynamoDbCostGovernanceReviewCollector(definition)
    evidence = wrapper.collect(ScannerContext(runtime=runtime, definition=definition))
    row = build_scanner_evidence_payload(scanner_id=SCANNER, evidence=evidence)
    implementation = wrapper.describe_implementation()
    warnings = runtime.warnings + session.collection_diagnostics.build_warning_messages_since(0)
    execution = ScannerExecutionResult(
        scanner_id=SCANNER,
        status="completed_with_warnings" if warnings else "completed",
        warnings=warnings,
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
        "provider_calls": {name: client.calls for name, client in session.clients.items()},
        "statuses": [result.status for result in session.collection_diagnostics.get_results_since(0)],
    }


def add_dynamodb_producer_payload(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Reuse populated actual records and all conditional configuration notes in smoke."""
    observed = dynamodb_producer_observation()
    for variant in ("summary", "billing_active"):
        for note in dynamodb_producer_observation(variant)["execution"]["coverage_notes"]:
            if note not in observed["execution"]["coverage_notes"]:
                observed["execution"]["coverage_notes"].append(note)
    if unknown:
        observed["evidence"]["payload"]["records"][0]["unknown_dynamodb_control"] = None
    add_wrapper_observation(files, observed)
