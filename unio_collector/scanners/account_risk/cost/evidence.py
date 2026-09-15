from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.account.risk import AccountCostRiskRecord
    from unio_collector.aws.cost_explorer import DailyCostRecord


@dataclass(frozen=True)
class AccountCostRiskEvidence:  # noqa: D101
    daily_costs: list[DailyCostRecord] = field(default_factory=list)
    account_risk: AccountCostRiskRecord | None = None
