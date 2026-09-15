from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
    from decimal import Decimal


@dataclass(frozen=True)
class MetricDatapoint:  # noqa: D101
    timestamp: datetime
    value: Decimal

    def convert_to_dict(self) -> dict[str, str]:  # noqa: D102
        return {
            "timestamp": self.timestamp.isoformat(),
            "value": str(self.value),
        }


__all__ = ["MetricDatapoint"]
