from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.audit_cost.inventory import KmsCostGovernanceRecord


@dataclass(frozen=True)
class KmsCostGovernanceEvidence:  # noqa: D101
    records: list[KmsCostGovernanceRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
