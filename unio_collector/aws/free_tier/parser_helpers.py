from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws.free_tier.response_parser import FreeTierResponseParser

if TYPE_CHECKING:
    from unio_collector.aws.free_tier.account_plan import FreeTierAccountPlanRecord
    from unio_collector.aws.free_tier.usage_record import FreeTierUsageRecord


def parse_account_plan(  # noqa: D103
    response: dict[str, Any],
    *,
    fallback_account_id: str,
) -> FreeTierAccountPlanRecord:
    return FreeTierResponseParser(
        fallback_account_id=fallback_account_id,
    ).parse_account_plan(response)


def parse_usage_record(value: dict[str, Any]) -> FreeTierUsageRecord:  # noqa: D103
    return FreeTierResponseParser(fallback_account_id="").parse_usage_record(value)
