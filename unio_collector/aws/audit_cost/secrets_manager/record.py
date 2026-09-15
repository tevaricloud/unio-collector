from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal

    from unio_collector.aws.audit_cost.secrets_manager.secret_evidence import SecretEvidence


@dataclass(frozen=True)
class SecretsManagerCostGovernanceRecord:  # noqa: D101
    account_id: str
    region: str
    secret_count: int = 0
    active_secret_count: int = 0
    scheduled_deletion_secret_count: int = 0
    rotation_enabled_secret_count: int = 0
    rotation_disabled_secret_count: int = 0
    old_access_secret_count: int = 0
    missing_last_access_secret_count: int = 0
    replica_secret_count: int = 0
    custom_kms_key_secret_count: int = 0
    service_managed_secret_count: int = 0
    customer_managed_secret_count: int = 0
    rotation_lambda_secret_count: int = 0
    tagged_secret_count: int = 0
    untagged_secret_count: int = 0
    sample_secret_names: list[str] = field(default_factory=list)
    sample_kms_key_ids: list[str] = field(default_factory=list)
    sample_rotation_disabled_secret_names: list[str] = field(default_factory=list)
    sample_old_access_secret_names: list[str] = field(default_factory=list)
    sample_untagged_secret_names: list[str] = field(default_factory=list)
    sample_service_managed_secret_names: list[str] = field(default_factory=list)
    sample_replica_regions: list[str] = field(default_factory=list)
    raw_secrets: list[SecretEvidence] | None = None
    derived_policy_fields_populated: bool = True
    analysis_limitations: list[str] = field(default_factory=list)
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    permission_errors: list[str] = field(default_factory=list)
