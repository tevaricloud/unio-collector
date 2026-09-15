from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class RedshiftRegionRecord:  # noqa: D101
    account_id: str
    region: str
    cluster_count: int = 0
    available_cluster_count: int = 0
    paused_cluster_count: int = 0
    total_node_count: int = 0
    multi_az_cluster_count: int = 0
    encrypted_cluster_count: int = 0
    logging_enabled_cluster_count: int = 0
    serverless_namespace_count: int = 0
    serverless_workgroup_count: int = 0
    serverless_base_capacity_rpu_total: int = 0
    serverless_max_capacity_rpu_total: int = 0
    sample_cluster_identifiers: list[str] = field(default_factory=list)
    sample_node_types: list[str] = field(default_factory=list)
    sample_serverless_names: list[str] = field(default_factory=list)
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    permission_errors: list[str] = field(default_factory=list)
