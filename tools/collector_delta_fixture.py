"""Actual Cost Explorer SDK collection, execution callbacks and serialization."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import date
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any, cast

from botocore.exceptions import ClientError

from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.api.call_ledger import ApiCallLedger
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.cost_explorer.collector import CostExplorerCollector
from unio_collector.core.scan.period_resolver import ScanPeriodResolver
from unio_collector.providers.aws.collection.fixture import AwsCollectionFixture
from unio_collector.scan_workflow.scanner.collection.service import ScannerCollectionService
from unio_collector.scan_workflow.scanner.runtime.cancellation import ScannerCancellationToken
from unio_collector.scan_workflow.scanner.runtime.dependencies import ScannerRuntimeDependencies
from unio_collector.scanners.cost_explorer.service_delta.collector import CostExplorerServiceDeltaCollector

SCANNER = "cost-explorer-service-delta"
VARIANTS = (
    "success",
    "empty",
    "pagination",
    "current_only",
    "previous_only",
    "deferred",
    "deferred_missing",
    "negative",
    "unknown_service",
    "denied",
    "unavailable",
    "unsupported",
    "failure",
    "interrupted",
    "fixture",
    "fixture_numeric",
    "fixture_no_region",
)


class SyntheticCostSession:
    """Finite synthetic read-only Cost Explorer provider and captured requests."""

    def __init__(self, variant: str) -> None:
        """Retain one isolated case and its request inventory."""
        self.variant = variant
        self.calls: list[dict[str, Any]] = []

    def create_client(self, service: str, *, region_name: str, audit_context: AwsAuditContext) -> SyntheticCostSession:
        """Reject unexpected services, regions or missing audited context."""
        if service != "ce" or region_name != "us-east-1" or audit_context is None:
            message = "Unexpected synthetic Cost Explorer request"
            raise AssertionError(message)
        return self

    def get_cost_and_usage(self, **kwargs: object) -> dict[str, Any]:
        """Return actual SDK-shaped service groups or declared failures."""
        self.calls.append(deepcopy(kwargs))
        variant = self.variant
        code = {
            "denied": "AccessDeniedException",
            "unavailable": "DataUnavailableException",
            "unsupported": "UnknownOperationException",
            "failure": "InternalServerException",
        }.get(variant)
        if code:
            raise ClientError({"Error": {"Code": code, "Message": "Synthetic provider limitation"}}, "GetCostAndUsage")
        if variant == "interrupted" and "NextPageToken" in kwargs:
            raise ClientError({"Error": {"Code": "LimitExceededException", "Message": "Synthetic interrupted page"}}, "GetCostAndUsage")
        period = cast("dict[str, str]", kwargs["TimePeriod"])
        previous = period["Start"] == "2026-09-17"
        service = "Synthetic customer service" if variant == "unknown_service" else "Amazon Simple Storage Service"
        amount = "-2.5" if variant == "negative" else "10.25" if previous else "30.50"
        groups = (
            []
            if variant == "empty" or (variant == "current_only" and previous) or (variant == "previous_only" and not previous)
            else [
                {"Keys": [service], "Metrics": {"UnblendedCost": {"Amount": amount, "Unit": "USD"}}},
                {"Keys": ["Amazon Elastic Compute Cloud - Compute"], "Metrics": {"UnblendedCost": {"Amount": "7.75", "Unit": "USD"}}},
            ]
        )
        response: dict[str, Any] = {"ResultsByTime": [{"TimePeriod": kwargs["TimePeriod"], "Estimated": False, "Groups": groups}]}
        if variant in {"pagination", "interrupted"} and "NextPageToken" not in kwargs:
            response["NextPageToken"] = "synthetic-cursor"
        return response


def delta_producer_observation(variant: str = "success") -> dict[str, Any]:
    """Run actual collection isolation, callbacks and canonical evidence recording."""
    if variant not in VARIANTS:
        message = "Unknown synthetic Cost Explorer variant"
        raise ValueError(message)
    session = SyntheticCostSession(variant)
    period = ScanPeriodResolver().resolve(days=7, reference_date=date(2026, 10, 1))
    definition = SimpleNamespace(scanner_id="cost-explorer-service-delta", display_name="synthetic")
    config = SimpleNamespace(absolute_threshold=Decimal("10.0"), percent_threshold=Decimal("20.0"), analysis_defaults_deferred=variant.startswith("deferred"))
    if variant == "deferred_missing":
        config.absolute_threshold = None
        config.percent_threshold = None
    collector = CostExplorerCollector(
        session, audit_context=AwsAuditContext(scanner_id=definition.scanner_id, collector="Synthetic Cost Explorer", allowed_api_calls=("ce:GetCostAndUsage",))
    )
    fixture_costs = None
    if variant.startswith("fixture"):
        collected = collector.collect_service_costs(scan_period=period)
        fixture_rows = deepcopy(collected.service_costs)
        for row in fixture_rows:
            row.pop("currency")
            if variant == "fixture_numeric":
                row["previous_cost"] = 2
                row["current_cost"] = 3.5
            if variant == "fixture_no_region":
                row.pop("region")
        raw = {
            "previous_period": collected.previous_period.model_dump(mode="json"),
            "current_period": collected.current_period.model_dump(mode="json"),
            "service_costs": fixture_rows,
        }
        with TemporaryDirectory(prefix="Unio-delta-fixture-") as scratch:
            path = Path(scratch) / "synthetic.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            fixture_costs = AwsCollectionFixture.read(path, default_currency="USD").costs
    events = []
    runner: Any = SimpleNamespace(
        runtime_state=SimpleNamespace(config=config, collection_diagnostics=None, ledger=ApiCallLedger()),
        note_state=SimpleNamespace(scanner_warnings={}, scanner_coverage_notes={}),
        output_state=SimpleNamespace(scanner_evidence_payloads=[], results=[]),
        active_attempt=None,
        cancellation_token=ScannerCancellationToken(),
        evidence_gateway=SimpleNamespace(
            collect_cached_service_costs=lambda _d: fixture_costs if fixture_costs is not None else collector.collect_service_costs(scan_period=period)
        ),
    )
    dependencies: Any = ScannerRuntimeDependencies(scanner_factory=lambda _id, d: CostExplorerServiceDeltaCollector(d), progress=events.append, scanner_total=1)
    execution = ScannerCollectionService(dependencies).collect_scanner(runner, SCANNER)
    if len(runner.output_state.results) != 1:
        message = "Synthetic collection did not record exactly one execution result"
        raise AssertionError(message)
    return {
        "evidence": runner.output_state.scanner_evidence_payloads[0] if runner.output_state.scanner_evidence_payloads else None,
        "calls": session.calls,
        "execution": execution.convert_to_dict(),
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


def add_delta_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Ship one actual two-window paginated financial producer, not merged DTOs."""
    observed = delta_producer_observation("pagination")
    row = observed["evidence"]
    if unknown:
        row["payload"]["result"]["service_costs"][0]["unknown_delta_control"] = False
    add_scanner_producer_payload(files, row, execution=observed["execution"])
