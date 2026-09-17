from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, ClassVar

from unio_collector.scanners.aws_native.collection.reader import AwsNativeOperationReader

if TYPE_CHECKING:
    from collections.abc import Iterable

    from unio_collector.aws_native_recommendations.recommendation.record import (
        AwsNativeRecommendationRecord,
    )


class AwsNativeRecommendationStatusPolicy:
    """Retain the public availability classifier without prose-based routing."""

    permission_codes: ClassVar[set[str]] = {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedException",
        "UnrecognizedClientException",
    }
    not_enabled_codes: ClassVar[set[str]] = {
        "OptInRequiredException",
        "OptInRequired",
        "AccountNotOptedInException",
        "SubscriptionRequiredException",
    }

    def classify_exception(self, exc: Exception) -> str:  # noqa: D102
        return AwsNativeOperationReader.classify_error_code(AwsNativeOperationReader.error_code(exc))

    def classify_payload_status(  # noqa: D102
        self,
        *,
        records: list[AwsNativeRecommendationRecord],
        statuses: Iterable[str],
    ) -> str:
        materialized = tuple(statuses)
        if not records and not materialized:
            return "unavailable"
        incomplete = [status for status in materialized if status not in {"complete", "recorded"}]
        if records and any(status != "capped" for status in incomplete):
            return "partial"
        if "capped" in incomplete:
            return "capped"
        if records:
            return "recorded"
        if "permission_limited" in materialized:
            return "permission_limited"
        if "not_enabled" in materialized:
            return "not_enabled"
        if "unavailable" in materialized:
            return "unavailable"
        if incomplete:
            return "unavailable"
        return "recorded_no_recommendations"
