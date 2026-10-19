"""Synthetic SDK responses driving both actual registered CloudFront wrappers."""

from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
from importlib import import_module
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

if TYPE_CHECKING:
    from collections.abc import Callable

from botocore.exceptions import ClientError

from tools.collector_edge.clock import SyntheticEdgeClock
from tools.collector_edge.responses import responses
from tools.collector_sdk_fixture import SyntheticWrapperRuntime
from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.core.scan.period_resolver import ScanPeriodResolver
from unio_collector.scanners.network.cloudfront_alb_protection.collector import CloudFrontAlbOriginProtectionReviewCollector
from unio_collector.scanners.network.cloudfront_origin.collector import CloudFrontOriginCostReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload
from unio_collector.scanners.scanner.result import ScannerExecutionResult

COLLECTORS = {
    "cloudfront-alb-origin-protection-review": CloudFrontAlbOriginProtectionReviewCollector,
    "cloudfront-origin-cost-review": CloudFrontOriginCostReviewCollector,
}
VARIANTS = ("success", "empty", "nullable", "partial", "denied", "unavailable", "unsupported", "failure", "vpc", "collision", "summary", "metrics")


class SyntheticEdgeSession:
    """Finite offline endpoints with operation recording and conditional provider errors."""

    def __init__(self, variant: str, calls: list[str] | None = None) -> None:
        """Retain one finite provider branch and its actual operation record."""
        self.variant = variant
        self.calls = [] if calls is None else calls
        self.runtime_config = AwsRuntimeConfig(max_workers=1)

    def create_client(self, service: str, **kwargs: object) -> SyntheticEdgeSession:
        """Refuse every endpoint outside the offline edge service/region inventory."""
        if service not in {"cloudfront", "elbv2", "ec2", "wafv2", "cloudwatch"} or kwargs.get("region_name") not in {"eu-west-2", "us-east-1"}:
            message = "Unexpected synthetic edge endpoint"
            raise AssertionError(message)
        return self

    def get_paginator(self, operation: str) -> SimpleNamespace:
        """Serve the declared one-page provider response through the real paginator interface."""
        return SimpleNamespace(paginate=lambda **kwargs: iter([getattr(self, operation)(**kwargs)]))

    def __getattr__(self, operation: str) -> Callable[..., dict[str, Any]]:
        """Expose only finite SDK operations, never a live fallback."""
        try:
            responses(operation, self.variant)
        except KeyError:
            raise AttributeError(operation) from None

        def invoke(**_kwargs: Any) -> dict[str, Any]:  # noqa: ANN401
            self.calls.append(operation)
            code = {"denied": "AccessDenied", "unavailable": "ServiceUnavailable", "unsupported": "UnsupportedOperation", "failure": "InternalFailure"}.get(
                self.variant
            )
            if self.variant == "partial" and operation in {"list_tags_for_resource", "get_origin_request_policy", "describe_rules", "get_web_acl_for_resource"}:
                code = "AccessDenied"
            if code:
                raise ClientError({"Error": {"Code": code, "Message": "synthetic-customer-provider-failure"}}, operation)
            if operation == "get_metric_data":
                return {
                    "MetricDataResults": [
                        {"Id": query["Id"], "Values": [17.0], "Timestamps": [datetime(2026, 1, 1, tzinfo=UTC)], "StatusCode": "Complete"}
                        for query in _kwargs["MetricDataQueries"]
                    ]
                }
            return responses(operation, self.variant)

        return invoke


def edge_producer_observation(scanner: str, variant: str = "success") -> dict[str, Any]:
    """Execute actual registered wrapper, gateways, callbacks and canonical serializer."""
    if scanner not in COLLECTORS or variant not in VARIANTS:
        message = "Unknown synthetic edge producer case"
        raise ValueError(message)
    session = SyntheticEdgeSession(variant)
    runtime: Any = SyntheticWrapperRuntime(
        session, options={"invalidation_detail_mode": "summary" if variant == "summary" else "full"}, service_costs=[], daily_costs=[]
    )
    runtime.runtime_state.config.scan_period = ScanPeriodResolver().resolve(date_from="2026-01-01", date_to="2026-01-31")
    runtime.runtime_state.config.allow_chargeable_scanners = variant == "metrics"
    definition: Any = SimpleNamespace(scanner_id=scanner, display_name=scanner)
    clock = (
        patch.object(import_module(COLLECTORS[scanner].__module__), "datetime", SyntheticEdgeClock)
        if scanner == "cloudfront-alb-origin-protection-review"
        else nullcontext()
    )
    with clock:
        evidence = COLLECTORS[scanner](definition).collect(ScannerContext(runtime=runtime, definition=definition))
    execution = ScannerExecutionResult(
        scanner_id=scanner,
        status="completed_with_warnings" if runtime.warnings else "completed",
        warnings=runtime.warnings,
        coverage_notes=runtime.notes,
        regions_scanned=getattr(evidence, "regions", []),
    ).convert_to_dict()
    return {
        "evidence": build_scanner_evidence_payload(scanner_id=scanner, evidence=evidence),
        "execution": execution,
        "callbacks": runtime.callbacks,
        "operations": session.calls,
    }
