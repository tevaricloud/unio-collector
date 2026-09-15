"""Currency-partitioned commitment value rollup."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class CommitmentCurrencyRollup:
    """Aggregate one compatible monetary metric within a currency partition."""

    service: str
    metric_name: str
    currency: str
    value: Decimal
    nature: str


__all__ = ["CommitmentCurrencyRollup"]
