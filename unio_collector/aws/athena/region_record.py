from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from unio_collector.aws.analytics.evidence.rows import NumericEvidenceRows  # noqa: TC001

if TYPE_CHECKING:
    from decimal import Decimal

    from unio_collector.aws.cost_explorer import UsageTypeCostSummary


@dataclass(frozen=True)
class AthenaRegionRecord:  # noqa: D101
    account_id: str
    region: str
    workgroup_count: int = 0
    unbounded_workgroup_count: int = 0
    enforced_workgroup_count: int = 0
    metrics_enabled_workgroup_count: int = 0
    requester_pays_workgroup_count: int = 0
    data_catalog_count: int = 0
    sample_workgroup_names: list[str] = field(default_factory=list)
    sample_data_catalog_names: list[str] = field(default_factory=list)
    query_execution_workgroups_checked: int = 0
    query_execution_count: int = 0
    failed_query_execution_count: int = 0
    long_running_query_count: int = 0
    high_bytes_scanned_query_count: int = 0
    total_bytes_scanned: int = 0
    total_engine_execution_ms: int = 0
    query_execution_collection_limited: bool = False
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    top_usage_type_costs: list[UsageTypeCostSummary] = field(default_factory=list)
    permission_errors: list[str] = field(default_factory=list)
    collection_evidence_version: int = 0
    query_numeric_evidence: NumericEvidenceRows | None = None
    configured_query_duration: int | None = None
    configured_query_bytes: int | None = None
    policy_input_source: int = 0
