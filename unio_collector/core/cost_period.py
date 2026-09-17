from __future__ import annotations  # noqa: D100

from datetime import date  # noqa: TC003
from decimal import Decimal  # noqa: TC003

from pydantic import field_validator

from unio_collector.core.base_model import UnioBaseModel


class CostPeriod(UnioBaseModel):
    """Cost Explorer period shared by collection, evidence, and reports."""

    start_date: date
    end_date: date
    total_cost: Decimal
    currency: str

    @field_validator("currency")
    @classmethod
    def normalize_currency(cls, value: str) -> str:  # noqa: D102
        return value.upper()
