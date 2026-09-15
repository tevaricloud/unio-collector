from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal

    from unio_collector.aws.audit_cost.cloudtrail.selector_evidence import (
        CloudTrailSelectorEvidence,
    )
    from unio_collector.aws.audit_cost.cloudtrail.store_evidence import (
        CloudTrailEventDataStoreEvidence,
    )


@dataclass(frozen=True)
class CloudTrailCostGovernanceRecord:  # noqa: D101
    account_id: str
    region: str
    trail_count: int = 0
    multi_region_trail_count: int = 0
    organization_trail_count: int = 0
    logging_trail_count: int = 0
    logging_stopped_trail_count: int = 0
    trail_status_error_count: int = 0
    trails_with_data_events: int = 0
    data_event_selector_count: int = 0
    advanced_event_selector_count: int = 0
    advanced_field_selector_count: int = 0
    data_resource_value_count: int = 0
    broad_data_resource_value_count: int = 0
    insight_selector_count: int = 0
    trails_with_insight_selectors: int = 0
    trails_with_management_events: int = 0
    logging_trails_with_management_events: int = 0
    event_data_store_count: int = 0
    event_data_store_long_retention_count: int = 0
    event_data_store_max_retention_days: int | None = None
    event_data_store_advanced_selector_count: int = 0
    log_file_validation_enabled_count: int = 0
    cloudwatch_logs_delivery_count: int = 0
    kms_encrypted_trail_count: int = 0
    s3_destination_count: int = 0
    sns_notification_count: int = 0
    management_event_selector_count: int = 0
    data_resource_types: list[str] = field(default_factory=list)
    selector_read_write_types: list[str] = field(default_factory=list)
    advanced_selector_names: list[str] = field(default_factory=list)
    sample_data_resource_values: list[str] = field(default_factory=list)
    sample_event_data_store_names: list[str] = field(default_factory=list)
    event_data_store_statuses: list[str] = field(default_factory=list)
    sample_s3_bucket_names: list[str] = field(default_factory=list)
    sample_cloudwatch_log_group_arns: list[str] = field(default_factory=list)
    sample_kms_key_ids: list[str] = field(default_factory=list)
    sample_home_regions: list[str] = field(default_factory=list)
    sample_trail_names: list[str] = field(default_factory=list)
    sample_management_event_trail_names: list[str] = field(default_factory=list)
    raw_selectors: list[CloudTrailSelectorEvidence] | None = None
    raw_event_data_stores: list[CloudTrailEventDataStoreEvidence] | None = None
    derived_policy_fields_populated: bool = True
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    permission_errors: list[str] = field(default_factory=list)
