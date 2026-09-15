from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class GuardDutyCostGovernanceRecord:  # noqa: D101
    account_id: str
    region: str
    detector_count: int = 0
    enabled_detector_count: int = 0
    enabled_feature_count: int = 0
    disabled_feature_count: int = 0
    feature_status_counts: dict[str, int] = field(default_factory=dict)
    finding_publishing_frequencies: list[str] = field(default_factory=list)
    detector_status_values: list[str] = field(default_factory=list)
    enabled_feature_names: list[str] = field(default_factory=list)
    sample_disabled_feature_names: list[str] = field(default_factory=list)
    sample_detector_ids: list[str] = field(default_factory=list)
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    permission_errors: list[str] = field(default_factory=list)
