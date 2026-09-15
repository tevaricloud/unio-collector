from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.audit_cost.inventory import WafCostGovernanceRecord


@dataclass(frozen=True)
class WafCostGovernanceEvidence:  # noqa: D101
    records: list[WafCostGovernanceRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
