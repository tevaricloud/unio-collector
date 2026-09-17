from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal

    from unio_collector.aws.audit_cost.kms.key_evidence import KmsKeyEvidence


@dataclass(frozen=True)
class KmsCostGovernanceRecord:  # noqa: D101
    account_id: str
    region: str
    listed_key_count: int = 0
    key_count: int = 0
    inaccessible_key_count: int = 0
    customer_managed_key_count: int = 0
    aws_managed_key_count: int = 0
    alias_classified_aws_managed_key_count: int = 0
    enabled_customer_key_count: int = 0
    disabled_customer_key_count: int = 0
    pending_deletion_key_count: int = 0
    multi_region_key_count: int = 0
    multi_region_primary_key_count: int = 0
    multi_region_replica_key_count: int = 0
    symmetric_key_count: int = 0
    asymmetric_key_count: int = 0
    hmac_key_count: int = 0
    external_origin_key_count: int = 0
    rotation_enabled_key_count: int = 0
    rotation_disabled_key_count: int = 0
    tagged_key_count: int = 0
    untagged_key_count: int = 0
    alias_count: int = 0
    customer_alias_count: int = 0
    sample_key_ids: list[str] = field(default_factory=list)
    sample_inaccessible_key_ids: list[str] = field(default_factory=list)
    sample_alias_classified_aws_managed_key_ids: list[str] = field(default_factory=list)
    sample_alias_names: list[str] = field(default_factory=list)
    sample_key_states: list[str] = field(default_factory=list)
    sample_key_specs: list[str] = field(default_factory=list)
    sample_key_usages: list[str] = field(default_factory=list)
    sample_key_origins: list[str] = field(default_factory=list)
    sample_multi_region_key_types: list[str] = field(default_factory=list)
    sample_disabled_key_ids: list[str] = field(default_factory=list)
    sample_pending_deletion_key_ids: list[str] = field(default_factory=list)
    sample_rotation_disabled_key_ids: list[str] = field(default_factory=list)
    raw_keys: list[KmsKeyEvidence] | None = None
    derived_policy_fields_populated: bool = True
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    permission_errors: list[str] = field(default_factory=list)
