"""Free Tier collection exports with explicit lazy application compatibility."""

from typing import TYPE_CHECKING, Any

from unio_collector.aws.free_tier.account_plan import FreeTierAccountPlanRecord
from unio_collector.aws.free_tier.api_error import FreeTierApiErrorRecorder
from unio_collector.aws.free_tier.collection_result import FreeTierCollectionResult
from unio_collector.aws.free_tier.collector import FreeTierCollector
from unio_collector.aws.free_tier.compatibility import resolve_free_tier_export
from unio_collector.aws.free_tier.facts import (
    FREE_TIER_REGION,
    is_account_plan_error,
    is_account_plan_expected_absence_error,
)
from unio_collector.aws.free_tier.formatting import (
    calculate_percentage,
    format_date_for_json,
    format_decimal_for_json,
    optional_string,
    parse_decimal,
)
from unio_collector.aws.free_tier.parser_helpers import (
    parse_account_plan,
    parse_usage_record,
)
from unio_collector.aws.free_tier.response_parser import FreeTierResponseParser
from unio_collector.aws.free_tier.usage_record import FreeTierUsageRecord

__all__ = [
    "FREE_TIER_REGION",
    "FreeTierAccountPlanRecord",
    "FreeTierApiErrorRecorder",
    "FreeTierCollectionResult",
    "FreeTierCollector",
    "FreeTierResponseParser",
    "FreeTierUsageRecord",
    "build_free_tier_limitations",
    "build_free_tier_visibility_messages",
    "calculate_percentage",
    "format_date_for_json",
    "format_decimal_for_json",
    "is_account_plan_error",
    "is_account_plan_expected_absence_error",
    "optional_string",
    "parse_account_plan",
    "parse_decimal",
    "parse_usage_record",
    "select_threshold_usage_records",
]


__getattr__ = resolve_free_tier_export

if TYPE_CHECKING:
    build_free_tier_limitations: Any
    build_free_tier_visibility_messages: Any
    select_threshold_usage_records: Any
