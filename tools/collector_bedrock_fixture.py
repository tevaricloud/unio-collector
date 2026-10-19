"""Synthetic Bedrock responses passed through the actual offline collection producer."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from tools.collector_sdk_fixture import add_wrapper_observation, wrapper_producer_observation
from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.aws.cost_explorer.result import CostExplorerResult
from unio_collector.aws.daily_cost_record import DailyCostRecord
from unio_collector.core.cost_period import CostPeriod

if TYPE_CHECKING:
    from unio_collector.aws.audit.context import AwsAuditContext


class SyntheticBedrockSession:
    """Implement only fixed in-memory responses; never construct an AWS client."""

    def __init__(self, variant: str) -> None:
        """Select the fixed synthetic response variant."""
        self.variant = variant
        self.runtime_config = AwsRuntimeConfig(max_workers=1)
        if variant == "client_model":
            self.meta = SimpleNamespace(service_model=SimpleNamespace(operation_names=[]))

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
        code = {
            "denied": "AccessDeniedException",
            "unsupported": "UnknownOperationException",
            "failure": "InternalFailure",
            "validation_unsupported": "ValidationException",
        }.get(self.variant)
        if code:
            raise ClientError(
                {"Error": {"Code": code, "Message": "unknown operation" if self.variant == "validation_unsupported" else "synthetic provider diagnostic"}},
                "ListCustomModels",
            )
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


def bedrock_producer_observation(variant: str = "success", *, billing: bool = True) -> dict[str, Any]:
    """Collect and serialize real DTOs with populated optional cost context."""
    session = SyntheticBedrockSession(variant)
    cost = None
    daily: list[DailyCostRecord] = []
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
    return wrapper_producer_observation("bedrock-cost-review", session, service_costs=cost, daily_costs=daily)


def bedrock_producer_payload(variant: str = "success", *, billing: bool = True) -> dict[str, Any]:
    """Retain the fixture API while collecting through the registered wrapper."""
    return bedrock_producer_observation(variant, billing=billing)["evidence"]


def add_bedrock_producer_payload(files: dict[str, bytes], *, unknown_field: bool = False) -> None:
    """Add one synthetic scanner envelope containing actual conditional records."""
    observed = bedrock_producer_observation()
    primary = observed["evidence"]
    for variant in ("denied", "unsupported", "failure", "unavailable"):
        additional = bedrock_producer_observation(variant, billing=False)
        primary["payload"]["records"].extend(additional["evidence"]["payload"]["records"])
        observed["execution"]["coverage_notes"].extend(additional["execution"]["coverage_notes"])
        observed["execution"]["warnings"].extend(additional["execution"]["warnings"])
    if unknown_field:
        primary["payload"]["records"][0]["top_usage_type_costs"][0]["unknown_synthetic_field"] = {}
    add_wrapper_observation(files, observed)
