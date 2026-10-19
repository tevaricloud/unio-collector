"""Actual NAT cost wrapper with offline topology, CloudWatch and daily-cost parsing."""

from __future__ import annotations

import json
from datetime import date
from types import SimpleNamespace
from typing import Any

from tools.collector_nat_fixture import REJECTED_VARIANTS, SyntheticNatSession
from tools.collector_nat_fixture import VARIANTS as INVENTORY_VARIANTS
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.cost_explorer.response_parser import CostExplorerResponseParser
from unio_collector.aws.network.inventory import NetworkInventoryCollector
from unio_collector.core.scan.period_resolver import ScanPeriodResolver
from unio_collector.scanners.network.nat_gateway.collector import NatGatewayCostReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

SCANNER = "nat-gateway-cost-review"
VARIANTS = (
    *[v for v in INVENTORY_VARIANTS if not v.startswith("legacy_")],
    *REJECTED_VARIANTS,
    "metrics_partial",
    "metrics_failed",
    "metrics_empty",
    "daily_empty",
    "daily_optional",
)


def nat_cost_producer_case(variant: str = "success") -> dict[str, Any]:
    """Use actual wrapper, inventory projection, metric reader, parser and serializer."""
    if variant not in VARIANTS:
        message = "Unknown synthetic NAT cost variant."
        raise ValueError(message)
    session = SyntheticNatSession(variant)
    definition: Any = SimpleNamespace(scanner_id=SCANNER)
    audit = AwsAuditContext(scanner_id=SCANNER, collector="NetworkInventoryCollector", allowed_api_calls=())
    collector = NetworkInventoryCollector(session, account_id="123456789012", audit_context=audit, selected_regions=["eu-west-2"])
    response = {
        "ResultsByTime": [
            {
                "TimePeriod": {"Start": "2026-05-19", "End": "2026-05-20"},
                "Groups": []
                if variant == "daily_empty"
                else [
                    {"Keys": ["Amazon Virtual Private Cloud", usage], "Metrics": {"UnblendedCost": {"Amount": amount, "Unit": "USD"}}}
                    for usage, amount in (("EUW2-NatGateway-Hours", "12.75"), ("EUW2-NatGateway-Bytes", "3.25"))
                ],
            }
        ]
    }
    if variant == "daily_optional":
        response["ResultsByTime"][0]["Groups"] = [{"Keys": ["Amazon Virtual Private Cloud"], "Metrics": {}}]
    runtime: Any = SimpleNamespace(
        runtime_state=SimpleNamespace(
            account_id="123456789012", config=SimpleNamespace(scan_period=ScanPeriodResolver().resolve(days=7, reference_date=date(2026, 5, 20)))
        ),
        get_cached_network_regions=lambda _d: ["eu-west-2"],
        create_network_collector=lambda *_args, **_kwargs: collector,
        collect_cached_network_batch=lambda _d, collection_name, **_kwargs: collector.collect_inventory_batch(collection_name),
        collect_cached_daily_costs=lambda _d, group_keys: CostExplorerResponseParser().parse_daily_cost_response(response, group_keys),
    )
    evidence = NatGatewayCostReviewCollector(definition).collect(ScannerContext(runtime=runtime, definition=definition))
    return json.loads(json.dumps(build_scanner_evidence_payload(scanner_id=SCANNER, evidence=evidence)))


def add_nat_cost_producer_payload(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Share populated factual metrics and daily financial observations with smoke."""
    row = nat_cost_producer_case()
    partial = nat_cost_producer_case("metrics_partial")
    row["payload"]["nat_gateways"].extend(partial["payload"]["nat_gateways"])
    if unknown:
        row["payload"]["daily_costs"][0]["unknown_nat_cost_container"] = {}
    add_scanner_producer_payload(files, row)
