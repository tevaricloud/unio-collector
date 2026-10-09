"""Synthetic Bedrock responses passed through the actual offline collection producer."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Any

from botocore.exceptions import ClientError

from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.analytics.ai import AnalyticsAiInventoryCollector
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.aws.cost_explorer.result import CostExplorerResult
from unio_collector.aws.daily_cost_record import DailyCostRecord
from unio_collector.core.cost_period import CostPeriod
from unio_collector.scanners.analytics_ai.bedrock.evidence import BedrockCostReviewEvidence
from unio_collector.scanners.cost_context import enrich_records_with_cost_context
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload


class SyntheticBedrockSession:
    """Implement only fixed in-memory responses; never construct an AWS client."""

    def __init__(self, variant: str) -> None:
        """Select the fixed synthetic response variant."""
        self.variant = variant
        self.runtime_config = AwsRuntimeConfig(max_workers=1)

    def create_client(self, service_name: str, *, region_name: str | None, audit_context: AwsAuditContext) -> SyntheticBedrockSession:
        """Supply only the explicitly requested synthetic service endpoints."""
        del audit_context
        if service_name not in {"bedrock", "bedrock-agent"} or region_name != "eu-west-2":
            message = "Synthetic Bedrock fixture received an unexpected service or region."
            raise ValueError(message)
        if self.variant == "unavailable":
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "synthetic unavailable service"}}, "CreateClient")
        return self

    def can_paginate(self, operation_name: str) -> bool:
        """Use one deterministic response page."""
        del operation_name
        return False

    def list_foundation_models(self, **kwargs: object) -> dict[str, Any]:
        """Return a public-catalog-shaped identifier."""
        del kwargs
        return {"modelSummaries": [{"modelId": "synthetic.foundation-model"}]}

    def list_custom_models(self, **kwargs: object) -> dict[str, Any]:
        """Exercise successful, denied, unsupported and failed producer branches."""
        del kwargs
        code = {"denied": "AccessDeniedException", "unsupported": "UnknownOperationException", "failure": "InternalFailure"}.get(self.variant)
        if code:
            raise ClientError({"Error": {"Code": code, "Message": "synthetic provider diagnostic"}}, "ListCustomModels")
        return {"modelSummaries": [{"modelName": "synthetic-customer-model"}]}

    def list_provisioned_model_throughputs(self, **kwargs: object) -> dict[str, Any]:
        """Return one customer-controlled name."""
        del kwargs
        return {"provisionedModelSummaries": [{"provisionedModelName": "synthetic-throughput"}]}

    def list_inference_profiles(self, **kwargs: object) -> dict[str, Any]:
        """Return one customer-controlled name."""
        del kwargs
        return {"inferenceProfileSummaries": [{"inferenceProfileName": "synthetic-profile"}]}

    def list_knowledge_bases(self, **kwargs: object) -> dict[str, Any]:
        """Return one customer-controlled name."""
        del kwargs
        return {"knowledgeBaseSummaries": [{"name": "synthetic-knowledge-base"}]}

    def list_agents(self, **kwargs: object) -> dict[str, Any]:
        """Return one customer-controlled name."""
        del kwargs
        return {"agentSummaries": [{"agentName": "synthetic-agent"}]}


def bedrock_producer_payload(variant: str = "success", *, billing: bool = True) -> dict[str, Any]:
    """Collect and serialize real DTOs with populated optional cost context."""
    collector = AnalyticsAiInventoryCollector(
        SyntheticBedrockSession(variant),
        account_id="123456789012",
        audit_context=AwsAuditContext(scanner_id="bedrock-cost-review", collector="synthetic", allowed_api_calls=()),
        selected_regions=["eu-west-2"],
    )
    records = collector.collect_bedrock_records()
    if billing:
        period = CostPeriod(start_date=date(2026, 9, 1), end_date=date(2026, 9, 30), total_cost=Decimal("17.25"), currency="USD")
        previous = CostPeriod(start_date=date(2026, 8, 1), end_date=date(2026, 8, 31), total_cost=Decimal("9.50"), currency="USD")
        cost = CostExplorerResult(
            previous_period=previous,
            current_period=period,
            service_costs=[
                {
                    "service_name": "Amazon Bedrock",
                    "current_cost": "17.25",
                    "previous_cost": "9.50",
                    "currency": "USD",
                }
            ],
        )
        daily = [
            DailyCostRecord(
                date=date(2026, 9, 1), service_name="Amazon Bedrock", region="eu-west-2", usage_type="synthetic-usage", cost=Decimal("17.25"), currency="USD"
            )
        ]
        records = enrich_records_with_cost_context(records, service_names=("Amazon Bedrock",), service_costs=cost, daily_costs=daily, usage_type_costs=daily)
    return build_scanner_evidence_payload(
        scanner_id="bedrock-cost-review", evidence=BedrockCostReviewEvidence(records=records, regions=collector.get_available_regions())
    )


def add_bedrock_producer_payload(files: dict[str, bytes], *, unknown_field: bool = False) -> None:
    """Add one synthetic scanner envelope containing actual conditional records."""
    primary = bedrock_producer_payload()
    for variant in ("denied", "unsupported", "failure", "unavailable"):
        primary["payload"]["records"].extend(bedrock_producer_payload(variant, billing=False)["payload"]["records"])
    if unknown_field:
        primary["payload"]["records"][0]["top_usage_type_costs"][0]["unknown_synthetic_field"] = {}
    add_scanner_producer_payload(files, primary)
