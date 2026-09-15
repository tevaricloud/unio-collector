from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class ConfigCostGovernanceRecord:  # noqa: D101
    account_id: str
    region: str
    recorder_count: int = 0
    recording_enabled_count: int = 0
    recording_stopped_count: int = 0
    delivery_channel_count: int = 0
    delivery_s3_bucket_count: int = 0
    delivery_sns_topic_count: int = 0
    all_supported_recording_count: int = 0
    include_global_resource_types_count: int = 0
    config_rule_count: int = 0
    aws_managed_rule_count: int = 0
    custom_rule_count: int = 0
    periodic_rule_count: int = 0
    change_triggered_rule_count: int = 0
    conformance_pack_count: int = 0
    targeted_resource_type_count: int = 0
    excluded_resource_type_count: int = 0
    continuous_recording_count: int = 0
    daily_recording_count: int = 0
    recorder_last_error_count: int = 0
    recording_strategy_types: list[str] = field(default_factory=list)
    recording_frequency_values: list[str] = field(default_factory=list)
    delivery_frequency_values: list[str] = field(default_factory=list)
    recorder_last_status_values: list[str] = field(default_factory=list)
    sample_recorded_resource_types: list[str] = field(default_factory=list)
    sample_excluded_resource_types: list[str] = field(default_factory=list)
    sample_recorder_names: list[str] = field(default_factory=list)
    sample_delivery_channel_names: list[str] = field(default_factory=list)
    sample_rule_names: list[str] = field(default_factory=list)
    sample_conformance_pack_names: list[str] = field(default_factory=list)
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    permission_errors: list[str] = field(default_factory=list)
