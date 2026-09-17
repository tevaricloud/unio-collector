from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class SecurityHubInspectorMacieCostGovernanceRecord:  # noqa: D101
    account_id: str
    region: str
    securityhub_enabled: bool = False
    securityhub_standard_count: int = 0
    securityhub_ready_standard_count: int = 0
    securityhub_non_ready_standard_count: int = 0
    securityhub_standard_statuses: list[str] = field(default_factory=list)
    sample_securityhub_standard_arns: list[str] = field(default_factory=list)
    inspector_enabled: bool = False
    inspector_status: str | None = None
    inspector_resource_statuses: list[str] = field(default_factory=list)
    macie_enabled: bool = False
    macie_status: str | None = None
    macie_finding_publishing_frequency: str | None = None
    macie_classification_job_count: int = 0
    macie_active_or_scheduled_job_count: int = 0
    macie_job_statuses: list[str] = field(default_factory=list)
    sample_macie_job_ids: list[str] = field(default_factory=list)
    macie_job_status_counts: dict[str, int] | None = None
    derived_policy_fields_populated: bool = True
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    permission_errors: list[str] = field(default_factory=list)
