from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal

    from unio_collector.aws.metric.summary import MetricSummary


@dataclass(frozen=True)
class ElastiCacheRegionRecord:  # noqa: D101
    account_id: str
    region: str
    cache_cluster_count: int = 0
    replication_group_count: int = 0
    available_cluster_count: int = 0
    total_node_count: int = 0
    multi_az_replication_group_count: int = 0
    automatic_failover_enabled_count: int = 0
    cluster_mode_enabled_count: int = 0
    sample_cluster_ids: list[str] = field(default_factory=list)
    sample_replication_group_ids: list[str] = field(default_factory=list)
    sample_engine_versions: list[str] = field(default_factory=list)
    metric_detail_collected: bool = True
    metric_cluster_count: int = 0
    metric_observation_count: int = 0
    low_activity_cluster_count: int = 0
    low_cpu_cluster_count: int = 0
    low_connection_cluster_count: int = 0
    eviction_signal_cluster_count: int = 0
    high_memory_pressure_cluster_count: int = 0
    sample_metric_cluster_ids: list[str] = field(default_factory=list)
    metric_cluster_ids: list[str] = field(default_factory=list)
    sample_low_activity_cluster_ids: list[str] = field(default_factory=list)
    sample_capacity_pressure_cluster_ids: list[str] = field(default_factory=list)
    metrics: list[MetricSummary] = field(default_factory=list)
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    permission_errors: list[str] = field(default_factory=list)
