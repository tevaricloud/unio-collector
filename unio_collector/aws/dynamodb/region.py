from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class DynamoDbRegionRecord:  # noqa: D101
    account_id: str
    region: str
    table_detail_collected: bool = True
    table_count: int = 0
    active_table_count: int = 0
    pay_per_request_table_count: int = 0
    provisioned_table_count: int = 0
    standard_ia_table_count: int = 0
    stream_enabled_table_count: int = 0
    pitr_enabled_table_count: int = 0
    pitr_disabled_table_count: int = 0
    ttl_enabled_table_count: int = 0
    ttl_disabled_table_count: int = 0
    global_secondary_index_count: int = 0
    provisioned_global_secondary_index_count: int = 0
    provisioned_table_without_autoscaling_count: int = 0
    provisioned_gsi_without_autoscaling_count: int = 0
    total_provisioned_read_capacity: int = 0
    total_provisioned_write_capacity: int = 0
    autoscaling_target_count: int = 0
    autoscaling_policy_count: int = 0
    tagged_table_count: int = 0
    untagged_table_count: int = 0
    sample_table_names: list[str] = field(default_factory=list)
    sample_pay_per_request_tables: list[str] = field(default_factory=list)
    sample_provisioned_tables: list[str] = field(default_factory=list)
    sample_standard_ia_tables: list[str] = field(default_factory=list)
    sample_stream_enabled_tables: list[str] = field(default_factory=list)
    sample_pitr_enabled_tables: list[str] = field(default_factory=list)
    sample_pitr_disabled_tables: list[str] = field(default_factory=list)
    sample_ttl_enabled_tables: list[str] = field(default_factory=list)
    sample_ttl_disabled_tables: list[str] = field(default_factory=list)
    sample_provisioned_tables_without_autoscaling: list[str] = field(
        default_factory=list,
    )
    sample_provisioned_gsis_without_autoscaling: list[str] = field(default_factory=list)
    sample_untagged_tables: list[str] = field(default_factory=list)
    sample_tag_keys: list[str] = field(default_factory=list)
    metric_table_count: int = 0
    metric_observation_count: int = 0
    consumed_capacity_table_count: int = 0
    throttle_signal_table_count: int = 0
    system_error_signal_table_count: int = 0
    average_daily_read_capacity_units: Decimal | None = None
    average_daily_write_capacity_units: Decimal | None = None
    sample_metric_table_names: list[str] = field(default_factory=list)
    observed_metric_names: list[str] = field(default_factory=list)
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    permission_errors: list[str] = field(default_factory=list)
