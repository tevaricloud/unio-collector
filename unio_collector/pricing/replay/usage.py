"""Typed serialized Cost Explorer usage input."""

from __future__ import annotations

from datetime import date  # noqa: TC003
from decimal import Decimal  # noqa: TC003

from unio_collector.aws.daily_cost_record import DailyCostRecord
from unio_collector.core.base_model import UnioBaseModel


class PricingUsageRecord(UnioBaseModel):
    """Serialized Cost Explorer usage input."""

    date: date
    service_name: str
    region: str
    usage_type: str | None = None
    cost: Decimal
    currency: str

    def to_daily_cost_record(self) -> DailyCostRecord:
        """Return the runtime pricing usage record."""
        return DailyCostRecord(**self.model_dump())
