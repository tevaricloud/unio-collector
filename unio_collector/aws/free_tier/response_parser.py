from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from unio_collector.aws.free_tier.account_plan import FreeTierAccountPlanRecord
from unio_collector.aws.free_tier.formatting import (
    format_date_for_json,
    optional_string,
    parse_decimal,
)
from unio_collector.aws.free_tier.usage_record import FreeTierUsageRecord
from unio_collector.aws.response_admission import ProviderResponseError, require_response_mapping

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class FreeTierResponseParser:
    """Parse AWS Free Tier API responses into typed usage records."""

    fallback_account_id: str

    def parse_account_plan(  # noqa: D102
        self,
        response: dict[str, Any],
    ) -> FreeTierAccountPlanRecord:
        response = require_response_mapping(response)
        for key in ("accountPlanType", "accountPlanStatus"):
            if not isinstance(response.get(key), str) or not response[key]:
                raise ProviderResponseError
        remaining_credits = response.get("accountPlanRemainingCredits")
        credit_amount = None
        credit_unit = None
        if remaining_credits is not None:
            remaining_credits = require_response_mapping(remaining_credits)
            credit_amount = self._provider_decimal(remaining_credits.get("amount"))
            unit = remaining_credits.get("unit")
            credit_unit = str(unit) if unit not in (None, "") else None
        return FreeTierAccountPlanRecord(
            account_id=str(response.get("accountId") or self.fallback_account_id),
            account_plan_type=optional_string(response.get("accountPlanType")),
            account_plan_status=optional_string(response.get("accountPlanStatus")),
            remaining_credit_amount=credit_amount,
            remaining_credit_unit=credit_unit,
            expiration_date=format_date_for_json(
                response.get("accountPlanExpirationDate"),
            ),
        )

    def parse_usage_record(self, value: dict[str, Any]) -> FreeTierUsageRecord:  # noqa: D102
        value = require_response_mapping(value)
        for key in ("service", "operation", "usageType"):
            if not isinstance(value.get(key), str) or not value[key]:
                raise ProviderResponseError
        return FreeTierUsageRecord(
            service=str(value.get("service") or "Unknown service"),
            operation=str(value.get("operation") or "unknown"),
            usage_type=str(value.get("usageType") or "unknown"),
            region=str(value.get("region") or "global"),
            actual_usage_amount=self._provider_decimal(value.get("actualUsageAmount")),
            forecasted_usage_amount=self._provider_decimal(value.get("forecastedUsageAmount")),
            limit=self._provider_decimal(value.get("limit")),
            unit=str(value.get("unit") or ""),
            description=str(value.get("description") or ""),
            free_tier_type=str(value.get("freeTierType") or ""),
        )

    def _provider_decimal(self, value: object) -> Decimal | None:
        parsed = parse_decimal(value)
        if value not in (None, "") and parsed is None:
            raise ProviderResponseError
        return parsed
