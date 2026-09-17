from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

from unio_collector.aws.free_tier.compatibility import resolve_free_tier_export
from unio_collector.aws.free_tier.facts import (
    is_account_plan_error,
)

if TYPE_CHECKING:
    from unio_collector.aws.free_tier.account_plan import FreeTierAccountPlanRecord
    from unio_collector.aws.free_tier.usage_record import FreeTierUsageRecord


@dataclass(frozen=True)
class FreeTierCollectionResult:  # noqa: D101
    account_id: str
    account_plan: FreeTierAccountPlanRecord | None = None
    usage_records: list[FreeTierUsageRecord] = field(default_factory=list)
    page_count: int = 0
    permission_errors: list[str] = field(default_factory=list)
    api_errors: list[str] = field(default_factory=list)

    def get_status(self) -> str:  # noqa: D102
        if self.permission_errors:
            return "permission_limited"
        if self.api_errors and not self.account_plan and not self.usage_records:
            return "unavailable"
        if self.account_plan or self.usage_records:
            return "available"
        return "no_usage_records"

    def get_account_plan_visibility_status(self) -> str:  # noqa: D102
        if self.account_plan:
            return "available"
        if self._has_account_plan_permission_error():
            return "permission_limited"
        if self._has_account_plan_api_error():
            return "unavailable"
        return "not_returned"

    def get_scanner_warning_messages(self) -> list[str]:
        """Preserve the historical application warning adapter."""
        return cast("list[str]", resolve_free_tier_export("build_free_tier_scanner_warnings")(self))

    def convert_to_summary(self) -> dict[str, Any]:
        """Build the historical application summary only on explicit request."""
        return cast("dict[str, Any]", resolve_free_tier_export("build_free_tier_summary")(self))

    def _has_account_plan_permission_error(self) -> bool:
        return any(is_account_plan_error(error) for error in self.permission_errors)

    def _has_account_plan_api_error(self) -> bool:
        return any(is_account_plan_error(error) for error in self.api_errors)
