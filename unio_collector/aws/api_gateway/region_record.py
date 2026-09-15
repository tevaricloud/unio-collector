from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class ApiGatewayRegionRecord:  # noqa: D101
    account_id: str
    region: str
    rest_api_count: int = 0
    http_api_count: int = 0
    websocket_api_count: int = 0
    private_rest_api_count: int = 0
    regional_rest_api_count: int = 0
    edge_optimized_rest_api_count: int = 0
    stage_count: int = 0
    auto_deploy_stage_count: int = 0
    cache_enabled_stage_count: int = 0
    access_logging_stage_count: int = 0
    execution_logging_stage_count: int = 0
    detailed_metrics_stage_count: int = 0
    data_trace_stage_count: int = 0
    xray_tracing_stage_count: int = 0
    route_count: int = 0
    authorization_configured_route_count: int = 0
    default_route_count: int = 0
    cors_configured_api_count: int = 0
    throttling_configured_stage_count: int = 0
    vpc_link_count: int = 0
    available_vpc_link_count: int = 0
    vpc_link_detail_collected: bool = True
    sample_endpoint_types: list[str] = field(default_factory=list)
    sample_api_names: list[str] = field(default_factory=list)
    sample_route_keys: list[str] = field(default_factory=list)
    sample_stage_names: list[str] = field(default_factory=list)
    sample_vpc_link_names: list[str] = field(default_factory=list)
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    permission_errors: list[str] = field(default_factory=list)
