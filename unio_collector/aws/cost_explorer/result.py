from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Any

from unio_collector.core.cost_period import CostPeriod  # noqa: TC001


@dataclass(frozen=True)
class CostExplorerResult:  # noqa: D101
    previous_period: CostPeriod
    current_period: CostPeriod
    service_costs: list[dict[str, Any]]
