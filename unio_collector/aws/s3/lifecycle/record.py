from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime
    from decimal import Decimal


@dataclass(frozen=True)
class S3BucketLifecycleRecord:  # noqa: D101
    bucket_name: str
    account_id: str
    region: str
    arn: str
    creation_date: datetime | None
    collection_profile: str = "full"
    skipped_metadata: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    bucket_tags_collected: bool = True
    bucket_lifecycle_collected: bool = True
    bucket_lifecycle_skip_reason: str | None = None
    lifecycle_priority_metric_collected: bool = False
    bucket_size_bytes: int | None = None
    bucket_object_count: int | None = None
    has_lifecycle_policy: bool = False
    lifecycle_rule_count: int = 0
    lifecycle_rule_summaries: list[dict[str, Any]] = field(default_factory=list)
    bucket_versioning_collected: bool = True
    bucket_versioning_skip_reason: str | None = None
    versioning_status: str | None = None
    has_noncurrent_version_expiration: bool = False
    has_noncurrent_version_transition: bool = False
    has_current_version_expiration: bool = False
    has_current_version_transition: bool = False
    has_abort_incomplete_multipart_upload: bool = False
    enabled_lifecycle_rule_count: int = 0
    disabled_lifecycle_rule_count: int = 0
    bucket_replication_collected: bool = True
    replication_enabled: bool = False
    replication_rule_count: int = 0
    enabled_replication_rule_count: int = 0
    replication_destinations: list[str] = field(default_factory=list)
    replication_rule_summaries: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
