from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
    from decimal import Decimal


@dataclass(frozen=True)
class MetricRequest:  # noqa: D101
    namespace: str
    metric_name: str
    dimensions: list[dict[str, str]]
    statistic: str
    period: int
    start_time: datetime
    end_time: datetime
    threshold_used: Decimal | None = None
    collection_context: int | None = None
