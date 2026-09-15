"""Commitment payment contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class CommitmentPayment:
    """Carry observed commitment payment terms without pricing inference."""

    payment_option: str | None = None
    upfront_amount: Decimal | None = None
    recurring_amount: Decimal | None = None
    recurring_unit: str | None = None
    currency: str | None = None
