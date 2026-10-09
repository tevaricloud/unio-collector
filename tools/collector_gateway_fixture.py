"""Actual gateway producer fixture using fixed offline provider responses."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Any

from botocore.exceptions import ClientError

from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.aws.cost_explorer.result import CostExplorerResult
from unio_collector.aws.daily_cost_record import DailyCostRecord
from unio_collector.aws.platform_inventory import ManagedPlatformInventoryCollector
from unio_collector.core.cost_period import CostPeriod
from unio_collector.scanners.cost_context import enrich_records_with_cost_context
from unio_collector.scanners.platform.api_gateway.evidence import ApiGatewayCostReviewEvidence
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

SCANNER = "api-gateway-cost-review"
VARIANTS = ("success", "empty", "denied", "unsupported", "partial", "unavailable", "summary", "failure")


class SyntheticGatewaySession:
    """Fixed synthetic endpoints; no network or SDK-client construction."""

    def __init__(self, variant: str) -> None:
        """Select a fixed offline provider-response branch."""
        self.variant = variant
        self.runtime_config = AwsRuntimeConfig(max_workers=1)
        self.vpc_calls = 0

    def create_client(self, service_name: str, *, region_name: str | None, audit_context: AwsAuditContext) -> SyntheticGatewaySession:
        """Return only this synthetic service endpoint; never construct an SDK client."""
        del audit_context
        if service_name not in ("apigateway", "apigatewayv2") or region_name != "eu-west-2":
            message = "Unexpected synthetic API Gateway service or region."
            raise ValueError(message)
        if self.variant == "unavailable":
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "Synthetic service unavailable"}}, "CreateClient")
        return self

    def can_paginate(self, name: str) -> bool:
        """Use the actual collector fallback path with one deterministic page."""
        del name
        return False

    def get_rest_apis(self, **_kwargs: object) -> dict[str, Any]:
        """Return the fixed synthetic response for this provider operation."""
        return {
            "items": []
            if self.variant == "empty"
            else [{"id": "synthetic-rest", "name": "synthetic-customer-rest", "endpointConfiguration": {"types": ["PRIVATE", "REGIONAL", "EDGE"]}}]
        }

    def get_apis(self, **_kwargs: object) -> dict[str, Any]:
        """Return the fixed synthetic response for this provider operation."""
        return {
            "Items": []
            if self.variant == "empty"
            else [
                {"ApiId": "synthetic-http", "Name": "synthetic-customer-http", "ProtocolType": "HTTP", "CorsConfiguration": {}},
                {"ApiId": "synthetic-websocket", "Name": "synthetic-customer-websocket", "ProtocolType": "WEBSOCKET"},
            ]
        }

    def get_stages(self, **_kwargs: object) -> dict[str, Any]:
        """Return the fixed synthetic response for this provider operation."""
        if self.variant in ("denied", "unsupported", "failure"):
            raise ClientError(
                {
                    "Error": {
                        "Code": {"denied": "AccessDeniedException", "unsupported": "UnknownOperationException", "failure": "InternalFailure"}[self.variant],
                        "Message": "Synthetic stage failure",
                    }
                },
                "GetStages",
            )
        row = {
            "stageName": "synthetic-customer-stage",
            "StageName": "synthetic-customer-stage",
            "cacheClusterEnabled": True,
            "tracingEnabled": True,
            "AutoDeploy": True,
            "accessLogSettings": {"destinationArn": "synthetic-destination"},
            "DefaultRouteSettings": {
                "DetailedMetricsEnabled": True,
                "DataTraceEnabled": True,
                "LoggingLevel": "INFO",
                "ThrottlingBurstLimit": 10,
                "ThrottlingRateLimit": 2.5,
            },
            "methodSettings": {"*/*": {"metricsEnabled": True, "dataTraceEnabled": True, "loggingLevel": "INFO", "throttlingBurstLimit": 10}},
        }
        return {"item": [row], "Items": [row]}

    def get_routes(self, **_kwargs: object) -> dict[str, Any]:
        """Return the fixed synthetic response for this provider operation."""
        if self.variant == "partial":
            raise ClientError({"Error": {"Code": "ThrottlingException", "Message": "Synthetic route throttled"}}, "GetRoutes")
        return {"Items": [{"RouteKey": "$default", "AuthorizationType": "AWS_IAM"}, {"RouteKey": "GET /synthetic-customer", "AuthorizationType": "JWT"}]}

    def get_vpc_links(self, **_kwargs: object) -> dict[str, Any]:
        """Return the fixed synthetic response for this provider operation."""
        self.vpc_calls += 1
        return {
            "items": [{"name": "synthetic-customer-vpc", "status": "AVAILABLE"}],
            "Items": [{"Name": "synthetic-customer-vpc", "VpcLinkStatus": "AVAILABLE"}],
        }


def gateway_producer_payload(variant: str = "success", *, billing: bool = True) -> dict[str, Any]:
    """Collect real DTOs and serialize optional cost-enriched producer output."""
    if variant not in VARIANTS:
        message = "Unknown synthetic inventory variant."
        raise ValueError(message)
    session = SyntheticGatewaySession(variant)
    collector = ManagedPlatformInventoryCollector(
        session,
        account_id="123456789012",
        audit_context=AwsAuditContext(scanner_id=SCANNER, collector="synthetic", allowed_api_calls=()),
        selected_regions=["eu-west-2"],
        api_gateway_vpc_link_detail_mode="summary" if variant == "summary" else "full",
    )
    records = collector.collect_api_gateway_records()
    if variant == "summary" and session.vpc_calls:
        message = "Summary collection unexpectedly requested VPC link details."
        raise AssertionError(message)
    if billing:
        current = CostPeriod(start_date=date(2026, 9, 1), end_date=date(2026, 9, 30), total_cost=Decimal("17.25"), currency="USD")
        previous = CostPeriod(start_date=date(2026, 8, 1), end_date=date(2026, 8, 31), total_cost=Decimal("9.50"), currency="USD")
        costs = CostExplorerResult(
            previous_period=previous,
            current_period=current,
            service_costs=[{"service_name": "Amazon API Gateway", "current_cost": "17.25", "previous_cost": "9.50", "currency": "USD"}],
        )
        daily = [
            DailyCostRecord(
                date=date(2026, 9, 1),
                service_name="Amazon API Gateway",
                region="eu-west-2",
                usage_type="synthetic-usage",
                cost=Decimal("17.25"),
                currency="USD",
            )
        ]
        records = enrich_records_with_cost_context(
            records, service_names=("Amazon API Gateway",), service_costs=costs, daily_costs=daily, usage_type_costs=daily
        )
    return build_scanner_evidence_payload(scanner_id=SCANNER, evidence=ApiGatewayCostReviewEvidence(records=records, regions=collector.get_available_regions()))


def add_gateway_producer_payload(files: dict[str, bytes], *, unknown_field: bool = False) -> None:
    """Use populated partial actual producer output in the distributed smoke input."""
    row = gateway_producer_payload("partial")
    if unknown_field:
        row["payload"]["records"][0]["unknown_gateway_field"] = {}
    add_scanner_producer_payload(files, row)
