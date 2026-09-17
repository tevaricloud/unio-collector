from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from unio_collector.aws.audit_cost.inventory import SecretsManagerCostGovernanceRecord


@dataclass(frozen=True)
class SecretsManagerCostGovernanceEvidence:  # noqa: D101
    records: list[SecretsManagerCostGovernanceRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    analysis_reference_instant: datetime | None = None
