from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from unio_collector.aws.free_tier.formatting import format_decimal_for_json

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class FreeTierAccountPlanRecord:  # noqa: D101
    account_id: str | None
    account_plan_type: str | None
    account_plan_status: str | None
    remaining_credit_amount: Decimal | None
    remaining_credit_unit: str | None
    expiration_date: str | None

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        return {
            "account_id": self.account_id,
            "account_plan_type": self.account_plan_type,
            "account_plan_status": self.account_plan_status,
            "remaining_credit_amount": format_decimal_for_json(
                self.remaining_credit_amount,
            ),
            "remaining_credit_unit": self.remaining_credit_unit,
            "expiration_date": self.expiration_date,
        }
