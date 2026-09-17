from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class WafCostGovernanceRecord:  # noqa: D101
    account_id: str
    region: str
    scope: str
    web_acl_count: int = 0
    web_acl_capacity_total: int = 0
    managed_rule_group_count: int = 0
    rate_based_rule_count: int = 0
    captcha_rule_count: int = 0
    challenge_rule_count: int = 0
    count_action_rule_count: int = 0
    allow_action_rule_count: int = 0
    block_action_rule_count: int = 0
    default_allow_acl_count: int = 0
    default_block_acl_count: int = 0
    rule_count: int = 0
    cloudwatch_metrics_enabled_count: int = 0
    sampled_requests_enabled_count: int = 0
    associated_resource_count: int = 0
    association_detail_mode: str = "full"
    association_metadata_collected: bool = True
    association_skip_reason: str | None = None
    associated_resource_types: list[str] = field(default_factory=list)
    rule_action_types: list[str] = field(default_factory=list)
    managed_rule_group_names: list[str] = field(default_factory=list)
    sample_rate_limits: list[int] = field(default_factory=list)
    sample_web_acl_names: list[str] = field(default_factory=list)
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    permission_errors: list[str] = field(default_factory=list)
