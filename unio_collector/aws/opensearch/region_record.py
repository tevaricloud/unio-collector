from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class OpenSearchRegionRecord:  # noqa: D101
    account_id: str
    region: str
    domain_count: int = 0
    processing_domain_count: int = 0
    total_instance_count: int = 0
    multi_az_domain_count: int = 0
    dedicated_master_domain_count: int = 0
    warm_storage_domain_count: int = 0
    ebs_enabled_domain_count: int = 0
    total_ebs_volume_gb: int = 0
    sample_domain_names: list[str] = field(default_factory=list)
    sample_engine_versions: list[str] = field(default_factory=list)
    sample_instance_types: list[str] = field(default_factory=list)
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    permission_errors: list[str] = field(default_factory=list)
