from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal

    from unio_collector.aws.cost_explorer import UsageTypeCostSummary


@dataclass(frozen=True)
class SageMakerRegionRecord:  # noqa: D101
    account_id: str
    region: str
    notebook_count: int = 0
    running_notebook_count: int = 0
    endpoint_count: int = 0
    in_service_endpoint_count: int = 0
    endpoint_variant_count: int = 0
    provisioned_endpoint_instance_count: int = 0
    serverless_endpoint_variant_count: int = 0
    async_endpoint_count: int = 0
    training_job_count: int = 0
    active_training_job_count: int = 0
    processing_job_count: int = 0
    active_processing_job_count: int = 0
    transform_job_count: int = 0
    active_transform_job_count: int = 0
    sample_notebook_names: list[str] = field(default_factory=list)
    sample_endpoint_names: list[str] = field(default_factory=list)
    sample_endpoint_instance_types: list[str] = field(default_factory=list)
    sample_training_job_names: list[str] = field(default_factory=list)
    sample_processing_job_names: list[str] = field(default_factory=list)
    sample_transform_job_names: list[str] = field(default_factory=list)
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    top_usage_type_costs: list[UsageTypeCostSummary] = field(default_factory=list)
    permission_errors: list[str] = field(default_factory=list)
