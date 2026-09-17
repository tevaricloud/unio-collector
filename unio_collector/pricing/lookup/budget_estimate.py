from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PricingLookupBudgetEstimate:  # noqa: D101
    lookup_request_count: int
    scheduled_lookup_request_count: int
    omitted_lookup_request_count: int
    estimated_api_call_count: int
    scheduled_estimated_api_call_count: int
    omitted_estimated_api_call_count: int
    estimated_api_call_budget: int | None
    estimated_pages_per_lookup: float
    timeout_seconds: int | None
    api_call_timeout_seconds: int | None
    rate_limit_requests_per_second: float | None
    estimated_minimum_seconds: int | None
    max_api_calls: int | None
    likely_to_complete_within_budget: bool
    pricing_budget_confidence: str
    note: str

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        return {
            "lookup_request_count": self.lookup_request_count,
            "scheduled_lookup_request_count": self.scheduled_lookup_request_count,
            "omitted_lookup_request_count": self.omitted_lookup_request_count,
            "estimated_api_call_count": self.estimated_api_call_count,
            "scheduled_estimated_api_call_count": (self.scheduled_estimated_api_call_count),
            "omitted_estimated_api_call_count": self.omitted_estimated_api_call_count,
            "estimated_api_call_budget": self.estimated_api_call_budget,
            "estimated_pages_per_lookup": self.estimated_pages_per_lookup,
            "timeout_seconds": self.timeout_seconds,
            "api_call_timeout_seconds": self.api_call_timeout_seconds,
            "total_job_timeout_seconds": self.timeout_seconds,
            "per_api_call_timeout_seconds": self.api_call_timeout_seconds,
            "rate_limit_requests_per_second": self.rate_limit_requests_per_second,
            "estimated_minimum_seconds": self.estimated_minimum_seconds,
            "max_api_calls": self.max_api_calls,
            "likely_to_complete_within_budget": self.likely_to_complete_within_budget,
            "pricing_budget_confidence": self.pricing_budget_confidence,
            "note": self.note,
        }
