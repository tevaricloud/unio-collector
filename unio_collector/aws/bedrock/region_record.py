from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from decimal import Decimal  # noqa: TC003

from unio_collector.aws.bedrock.operation_limitation import (  # noqa: TC001
    BedrockOperationLimitation,
)
from unio_collector.aws.cost_explorer import UsageTypeCostSummary  # noqa: TC001


@dataclass(frozen=True)
class BedrockRegionRecord:  # noqa: D101
    account_id: str
    region: str
    foundation_model_count: int = 0
    custom_model_count: int = 0
    provisioned_throughput_count: int = 0
    inference_profile_count: int = 0
    agent_count: int = 0
    knowledge_base_count: int = 0
    sample_foundation_model_ids: list[str] = field(default_factory=list)
    sample_custom_model_names: list[str] = field(default_factory=list)
    sample_provisioned_model_names: list[str] = field(default_factory=list)
    sample_inference_profile_names: list[str] = field(default_factory=list)
    sample_agent_names: list[str] = field(default_factory=list)
    sample_knowledge_base_names: list[str] = field(default_factory=list)
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    top_usage_type_costs: list[UsageTypeCostSummary] = field(default_factory=list)
    permission_errors: list[str] = field(default_factory=list)
    operation_limitations: list[BedrockOperationLimitation] = field(
        default_factory=list,
    )
