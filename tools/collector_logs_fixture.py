"""Actual CloudWatch Logs wrappers exercised with synthetic SDK responses."""

from __future__ import annotations

import json
from datetime import date
from types import SimpleNamespace
from typing import Any

from botocore.exceptions import ClientError

from tools.collector_balancer_fixture import SyntheticBalancerSession
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.cloudwatch.log.collector import CloudWatchLogsCollector
from unio_collector.core.scan.period_resolver import ScanPeriodResolver
from unio_collector.scanners.cloudwatch.log_activity.idle import CloudWatchIdleLogReviewCollector
from unio_collector.scanners.cloudwatch.log_cost.collector import CloudWatchLogCostRelevanceCollector
from unio_collector.scanners.cloudwatch.log_retention.collector import CloudWatchLogRetentionCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

SCANNERS = {
    "cloudwatch-log-groups-without-retention": CloudWatchLogRetentionCollector,
    "cloudwatch-idle-log-review": CloudWatchIdleLogReviewCollector,
    "cloudwatch-log-cost-and-relevance-review": CloudWatchLogCostRelevanceCollector,
}
ACTIVITY_SCANNERS = tuple(name for name in SCANNERS if name != "cloudwatch-log-groups-without-retention")
VARIANTS = (
    "success",
    "optional",
    "empty",
    "denied",
    "unsupported",
    "unavailable",
    "failure",
    "partial",
    "retained",
    "metrics_failed",
    "metrics_partial",
    "metrics_empty",
    "quiet_retained",
)


class SyntheticLogsSession(SyntheticBalancerSession):
    """Share synthetic metric responses while restricting the logs endpoints."""

    def create_client(self, service_name: str, *, region_name: str | None, audit_context: AwsAuditContext) -> SyntheticLogsSession:
        """Never construct an SDK client or accept an unknown endpoint."""
        del audit_context
        if service_name not in {"logs", "cloudwatch"} or region_name != "eu-west-2":
            message = "Unexpected synthetic logs endpoint."
            raise ValueError(message)
        return self

    def describe_log_groups(self, **kwargs: object) -> dict[str, Any]:
        """Return populated, optional, filtered and interrupted inventory pages."""
        code = {
            "denied": "AccessDeniedException",
            "unsupported": "UnsupportedOperation",
            "unavailable": "ServiceUnavailable",
            "failure": "InternalFailure",
        }.get(self.variant)
        if self.variant == "partial" and kwargs.get("nextToken"):
            code = "ThrottlingException"
        if code:
            raise ClientError({"Error": {"Code": code, "Message": "Synthetic unavailable endpoint"}}, "DescribeLogGroups")
        groups: list[dict[str, Any]] = [
            {"logGroupName": "/synthetic/customer-one", "storedBytes": 1234, "creationTime": 1770000000000},
            {"logGroupName": "/synthetic/customer-two", "storedBytes": 12, "creationTime": 1770000000000},
        ]
        if self.variant == "optional":
            groups = [{"logGroupName": "/synthetic/customer-optional"}]
        if self.variant in {"retained", "quiet_retained"}:
            for row in groups:
                row["retentionInDays"] = 30
                if self.variant == "quiet_retained":
                    row["storedBytes"] = 0
        return {"logGroups": [] if self.variant == "empty" else groups, **({"nextToken": "synthetic-next"} if self.variant == "partial" else {})}

    def get_metric_data(self, **kwargs: Any) -> dict[str, Any]:  # noqa: ANN401
        """Exercise actual parser/aggregation with a separate zero-ingestion branch."""
        result = super().get_metric_data(**kwargs)
        if self.variant == "quiet_retained":
            for row in result["MetricDataResults"]:
                row["Values"] = [0]
        return result


def logs_producer_case(
    scanner: str, variant: str = "success", mode: str = "full", idle_days: int = 30
) -> tuple[dict[str, Any], list[str], list[dict[str, Any]]]:
    """Cross actual wrappers, gateways, inventory, metrics and JSON serialization."""
    if scanner not in SCANNERS or variant not in VARIANTS or mode not in {"full", "regional", "global"}:
        message = "Unknown synthetic logs case."
        raise ValueError(message)
    session = SyntheticLogsSession(variant)
    definition: Any = SimpleNamespace(scanner_id=scanner)
    notes: list[dict[str, Any]] = []
    collector = CloudWatchLogsCollector(
        session, audit_context=AwsAuditContext(scanner_id=scanner, collector="CloudWatchLogsCollector", allowed_api_calls=()), selected_regions=["eu-west-2"]
    )
    period = ScanPeriodResolver().resolve(days=7, reference_date=date(2026, 5, 20))
    options = {
        "metric_detail_mode": "full" if mode == "full" else "prioritized",
        "metric_prioritization_scope": "global" if mode == "global" else "regional",
        "max_metric_log_groups_per_region": 1,
        "max_metric_log_groups": 1,
        "idle_days": idle_days,
    }
    runtime: Any = SimpleNamespace(
        runtime_state=SimpleNamespace(get_scanner_option=lambda _s, key, default: options.get(key, default)),
        create_cloudwatch_logs_collector=lambda _d: collector,
        collect_cached_log_groups_without_retention=lambda _d: collector.collect_log_groups_without_retention(),
        collect_cached_log_group_activity=lambda _d, metric_options: collector.collect_log_group_activity(period, metric_options),
        add_scanner_coverage_note=lambda _s, note: notes.append(note),
    )
    evidence = SCANNERS[scanner](definition).collect(ScannerContext(runtime=runtime, definition=definition))
    row = json.loads(json.dumps(build_scanner_evidence_payload(scanner_id=scanner, evidence=evidence)))
    return row, [value.status for value in session.collection_diagnostics.get_results_since(0)], notes


def add_logs_producer_payload(files: dict[str, bytes], *, unknown_field: bool = False) -> None:
    """Share actual complete, partial, skipped and nullable records with native smoke."""
    for scanner in SCANNERS:
        row, _, _ = logs_producer_case(scanner)
        variants = (("optional", "full"),) if scanner not in ACTIVITY_SCANNERS else (("optional", "full"), ("success", "regional"), ("metrics_partial", "full"))
        for variant, mode in variants:
            extra, _, _ = logs_producer_case(scanner, variant, mode)
            row["payload"]["records"].extend(extra["payload"]["records"])
        if unknown_field and scanner in ACTIVITY_SCANNERS:
            row["payload"]["records"][0]["metrics"][0]["unknown_log_metric"] = {}
        add_scanner_producer_payload(files, row)
