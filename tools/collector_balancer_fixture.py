"""Synthetic SDK responses exercising actual load-balancer and metric producers."""

from __future__ import annotations

import json
from datetime import date
from decimal import Decimal
from types import SimpleNamespace
from typing import Any

from botocore.exceptions import ClientError

from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.aws.collection.diagnostics import AwsCollectionDiagnostics
from unio_collector.core.scan.period_resolver import ScanPeriodResolver
from unio_collector.scanners.collection.load_balancer import LoadBalancerIdleReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

SCANNER = "load-balancer-idle-review"
VARIANTS = (
    "success",
    "optional",
    "empty",
    "denied",
    "unsupported",
    "unavailable",
    "failure",
    "groups_failed",
    "health_failed",
    "tags_failed",
    "metrics_failed",
    "metrics_partial",
    "metrics_empty",
)


class SyntheticBalancerSession:
    """Serve only known synthetic endpoints without constructing SDK clients."""

    def __init__(self, variant: str) -> None:
        """Select deterministic collection behavior and retain real diagnostics."""
        self.variant = variant
        self.runtime_config = AwsRuntimeConfig(max_workers=1)
        self.collection_diagnostics = AwsCollectionDiagnostics()

    def create_client(self, service_name: str, *, region_name: str | None, audit_context: AwsAuditContext) -> SyntheticBalancerSession:
        """Reject unexpected service/region requests rather than using a provider."""
        del audit_context
        if service_name not in {"elbv2", "cloudwatch"} or region_name != "eu-west-2":
            message = "Unexpected synthetic load-balancer endpoint."
            raise ValueError(message)
        return self

    def can_paginate(self, operation: str) -> bool:
        """Exercise deterministic token pagination without a paginator dependency."""
        del operation
        return False

    def describe_load_balancers(self, **_kwargs: object) -> dict[str, Any]:
        """Produce current inventory including empty, optional and unavailable cases."""
        codes = {"denied": "AccessDenied", "unsupported": "UnsupportedOperation", "unavailable": "ServiceUnavailable", "failure": "InternalFailure"}
        if self.variant in codes:
            raise ClientError({"Error": {"Code": codes[self.variant], "Message": "Synthetic unavailable endpoint"}}, "DescribeLoadBalancers")
        records = []
        for kind, segment in (("application", "app"), ("network", "net")):
            row: dict[str, Any] = {"LoadBalancerArn": f"arn:aws:elasticloadbalancing:eu-west-2:123456789012:loadbalancer/{segment}/synthetic/0000000000000000"}
            if self.variant != "optional":
                row.update(LoadBalancerName="synthetic-customer-balancer", Type=kind, State={"Code": "active"})
            records.append(row)
        return {"LoadBalancers": [] if self.variant == "empty" else records}

    def describe_target_groups(self, **_kwargs: object) -> dict[str, Any]:
        """Exercise group discovery and its incomplete-evidence branch."""
        if self.variant == "groups_failed":
            message = "Synthetic group failure."
            raise ValueError(message)
        return {"TargetGroups": [{"TargetGroupArn": "arn:aws:elasticloadbalancing:eu-west-2:123456789012:targetgroup/synthetic/0000000000000000"}]}

    def describe_target_health(self, **_kwargs: object) -> dict[str, Any]:
        """Retain actual unavailable-health semantics."""
        if self.variant == "health_failed":
            message = "Synthetic health failure."
            raise ValueError(message)
        return {"TargetHealthDescriptions": [{"TargetHealth": {"State": "healthy"}}]}

    def describe_tags(self, **kwargs: Any) -> dict[str, Any]:  # noqa: ANN401
        """Populate customer-controlled tags or fail their independent collection."""
        if self.variant == "tags_failed":
            message = "Synthetic tag failure."
            raise ValueError(message)
        return {
            "TagDescriptions": [{"ResourceArn": arn, "Tags": [{"Key": "Name", "Value": "synthetic-customer-load-balancer"}]} for arn in kwargs["ResourceArns"]]
        }

    def get_metric_data(self, **kwargs: Any) -> dict[str, Any]:  # noqa: ANN401
        """Use real parsing/aggregation for complete, partial, empty and failed reads."""
        if self.variant == "metrics_failed":
            message = "Synthetic metric failure."
            raise ValueError(message)
        return {
            "MetricDataResults": [
                {
                    "Id": query["Id"],
                    "Values": [] if self.variant == "metrics_empty" else [Decimal(2)],
                    "Timestamps": [] if self.variant == "metrics_empty" else [kwargs["StartTime"]],
                    "StatusCode": "PartialData" if self.variant == "metrics_partial" else "Complete",
                }
                for query in kwargs["MetricDataQueries"]
            ]
        }

    def get_metric_statistics(self, **_kwargs: object) -> dict[str, Any]:
        """Exercise unavailable fallback without using a real provider."""
        if self.variant == "metrics_failed":
            message = "Synthetic metric fallback failure."
            raise ValueError(message)
        return {"Datapoints": []}


def balancer_producer_case(variant: str = "success", mode: str = "full", *, tags: bool = True) -> tuple[dict[str, Any], list[str]]:
    """Invoke the actual wrapper, gateways, inventory and current metric DTO path."""
    if variant not in VARIANTS or mode not in {"full", "summary"}:
        message = "Unknown synthetic load-balancer variant."
        raise ValueError(message)
    session = SyntheticBalancerSession(variant)
    options = {"target_health_detail_mode": mode, "collect_tags": tags}
    definition: Any = SimpleNamespace(scanner_id=SCANNER)
    runtime: Any = SimpleNamespace(
        runtime_state=SimpleNamespace(
            session=session,
            account_id="123456789012",
            get_selected_regions=lambda: ["eu-west-2"],
            get_scanner_option=lambda _s, key, default: options.get(key, default),
            config=SimpleNamespace(scan_period=ScanPeriodResolver().resolve(days=7, reference_date=date(2026, 5, 20))),
        ),
        create_audit_context=lambda _d, name: AwsAuditContext(scanner_id=SCANNER, collector=name, allowed_api_calls=()),
        add_scanner_coverage_note=lambda _s, _note: None,
    )
    evidence = LoadBalancerIdleReviewCollector(definition).collect(ScannerContext(runtime=runtime, definition=definition))

    row = json.loads(json.dumps(build_scanner_evidence_payload(scanner_id=SCANNER, evidence=evidence)))
    return row, [result.status for result in session.collection_diagnostics.get_results_since(0)]


def add_balancer_producer_payload(files: dict[str, bytes], *, unknown_field: bool = False) -> None:
    """Share populated and partial current metric evidence with native smoke."""
    row, _ = balancer_producer_case()
    partial, _ = balancer_producer_case("metrics_partial")
    row["payload"]["records"].extend(partial["payload"]["records"])
    if unknown_field:
        row["payload"]["records"][0]["metrics"][0]["unknown_balancer_field"] = {}
    add_scanner_producer_payload(files, row)
