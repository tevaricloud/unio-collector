from __future__ import annotations  # noqa: D100

from decimal import Decimal  # noqa: TC003
from typing import Literal

from pydantic import Field, field_validator

from unio_collector.billing.period import CompletedMonthPeriod  # noqa: TC001
from unio_collector.core.base_model import UnioBaseModel

BillingBaselineStatus = Literal[
    "available",
    "unavailable",
    "not_collected",
    "permission_denied",
    "incomplete",
    "period_mismatch",
    "invalid",
]


class LastCompletedMonthBillingBaseline(UnioBaseModel):
    """Validated AWS billing evidence for the last completed calendar month."""

    period: CompletedMonthPeriod
    amount: Decimal | None = None
    currency: str | None = None
    source: str = "AWS Cost Explorer"
    api_operation: str = "GetCostAndUsage"
    metric: str = "UnblendedCost"
    estimated: bool | None = None
    complete: bool = False
    status: BillingBaselineStatus = "unavailable"
    limitations: list[str] = Field(default_factory=list)

    @field_validator("currency")
    @classmethod
    def normalize_currency(cls, value: str | None) -> str | None:
        """Normalize an optional AWS billing currency code."""
        return value.upper() if value else None
