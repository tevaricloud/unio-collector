from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws.client.config import AwsRuntimeConfig, RateLimitRule
from unio_collector.pricing.lookup.budget_estimate import PricingLookupBudgetEstimate

if TYPE_CHECKING:
    from unio_collector.pricing.lookup.request import PricingLookupRequest


class AwsPricingRateBudgetMixin:
    """Pricing lookup budget and schedule helpers for AWS rate providers."""

    @property
    def _provider(self) -> Any:  # noqa: ANN401
        return self

    def _build_budget_estimate(
        self,
        requests: list[PricingLookupRequest],
        *,
        timeout_seconds: int | None,
        api_call_timeout_seconds: int | None,
        max_api_calls: int | None,
    ) -> PricingLookupBudgetEstimate:
        request_count = len(requests)
        estimated_request_api_calls = [self._estimate_request_api_call_count(request) for request in requests]
        estimated_api_call_count = sum(estimated_request_api_calls)
        if request_count == 0:
            return PricingLookupBudgetEstimate(
                lookup_request_count=0,
                scheduled_lookup_request_count=0,
                omitted_lookup_request_count=0,
                estimated_api_call_count=0,
                scheduled_estimated_api_call_count=0,
                omitted_estimated_api_call_count=0,
                estimated_api_call_budget=0,
                estimated_pages_per_lookup=0.0,
                timeout_seconds=timeout_seconds,
                api_call_timeout_seconds=api_call_timeout_seconds,
                rate_limit_requests_per_second=None,
                estimated_minimum_seconds=None,
                max_api_calls=max_api_calls,
                likely_to_complete_within_budget=True,
                pricing_budget_confidence="high",
                note="No pricing lookup requests were required.",
            )
        rate_rule = self._get_pricing_rate_rule()
        rate_per_second = rate_rule.requests_per_second if rate_rule else None
        estimated_minimum_seconds = int((estimated_api_call_count / rate_per_second) + 0.999) if rate_per_second else None
        estimated_api_call_budget: int | None = estimated_api_call_count
        if timeout_seconds is not None and rate_per_second:
            available_seconds = max(
                0,
                timeout_seconds - int(api_call_timeout_seconds or 0),
            )
            safe_call_budget = int(available_seconds * rate_per_second * 0.75)
            estimated_api_call_budget = max(1, safe_call_budget)
        if max_api_calls is not None:
            estimated_api_call_budget = min(
                estimated_api_call_budget or max_api_calls,
                max(0, max_api_calls),
            )
        scheduled_count = self._count_scheduled_requests_for_budget(
            requests,
            max_api_calls,
        )
        scheduled_estimated_api_call_count = sum(
            estimated_request_api_calls[:scheduled_count],
        )
        omitted_count = max(0, request_count - scheduled_count)
        omitted_estimated_api_call_count = max(
            0,
            estimated_api_call_count - scheduled_estimated_api_call_count,
        )
        time_budget_limited = (timeout_seconds is not None and estimated_minimum_seconds is not None and estimated_minimum_seconds > timeout_seconds) or (
            estimated_api_call_budget is not None and estimated_api_call_count > estimated_api_call_budget
        )
        likely_to_complete = omitted_count == 0 and not time_budget_limited
        estimated_pages_per_lookup = round(
            estimated_api_call_count / request_count,
            2,
        )
        budget_confidence = self._classify_budget_confidence(
            requests,
            omitted_count=omitted_count,
            time_budget_limited=time_budget_limited,
        )
        note = self._build_budget_note(
            likely_to_complete=likely_to_complete,
            omitted_count=omitted_count,
            time_budget_limited=time_budget_limited,
        )
        return PricingLookupBudgetEstimate(
            lookup_request_count=request_count,
            scheduled_lookup_request_count=scheduled_count,
            omitted_lookup_request_count=omitted_count,
            estimated_api_call_count=estimated_api_call_count,
            scheduled_estimated_api_call_count=scheduled_estimated_api_call_count,
            omitted_estimated_api_call_count=omitted_estimated_api_call_count,
            estimated_api_call_budget=estimated_api_call_budget,
            estimated_pages_per_lookup=estimated_pages_per_lookup,
            timeout_seconds=timeout_seconds,
            api_call_timeout_seconds=api_call_timeout_seconds,
            rate_limit_requests_per_second=rate_per_second,
            estimated_minimum_seconds=estimated_minimum_seconds,
            max_api_calls=max_api_calls,
            likely_to_complete_within_budget=likely_to_complete,
            pricing_budget_confidence=budget_confidence,
            note=note,
        )

    def _select_lookup_requests_for_budget(
        self,
        requests: list[PricingLookupRequest],
        estimated_api_call_budget: int | None,
    ) -> list[PricingLookupRequest]:
        scheduled_count = self._count_scheduled_requests_for_budget(
            requests,
            estimated_api_call_budget,
        )
        return requests[:scheduled_count]

    def _count_scheduled_requests_for_budget(
        self,
        requests: list[PricingLookupRequest],
        estimated_api_call_budget: int | None,
    ) -> int:
        if estimated_api_call_budget is None:
            return len(requests)
        if estimated_api_call_budget <= 0:
            return 0
        scheduled_count = 0
        estimated_calls = 0
        for request in requests:
            request_call_count = self._estimate_request_api_call_count(request)
            if scheduled_count > 0 and (estimated_calls + request_call_count > estimated_api_call_budget):
                break
            scheduled_count += 1
            estimated_calls += request_call_count
        return scheduled_count

    def _estimate_request_api_call_count(
        self,
        request: PricingLookupRequest,
    ) -> int:
        del request
        return 1

    def _classify_budget_confidence(
        self,
        requests: list[PricingLookupRequest],
        *,
        omitted_count: int,
        time_budget_limited: bool,
    ) -> str:
        if not requests:
            return "high"
        if omitted_count:
            return "medium"
        if time_budget_limited:
            return "medium"
        if any(self._estimate_request_api_call_count(request) > 1 for request in requests):
            return "medium"
        return "high"

    def _build_budget_note(
        self,
        *,
        likely_to_complete: bool,
        omitted_count: int,
        time_budget_limited: bool,
    ) -> str:
        if likely_to_complete:
            return "Planned pricing lookup requests are expected to fit the configured budget based on conservative Price List page estimates."
        if omitted_count:
            return (
                "Unio Collector scheduled the highest-priority pricing lookups that fit "
                "the configured hard API call limit and omitted the rest from live "
                "pricing enrichment for this run."
            )
        if time_budget_limited:
            return (
                "Unio Collector will attempt all pricing lookups, but conservative page "
                "estimates exceed the configured timeout. The run may still complete "
                "when AWS returns fewer pages than estimated."
            )
        return "Unio Collector will attempt the selected pricing lookups and stop safely if the configured timeout or API call limit is reached."

    def _get_pricing_rate_rule(self) -> RateLimitRule | None:
        runtime_config = getattr(self._provider.session, "runtime_config", None)
        if runtime_config is None:
            runtime_config = AwsRuntimeConfig()
        operation_rule = runtime_config.operation_rate_limits.get("pricing:GetProducts")
        if operation_rule is not None:
            return operation_rule
        return runtime_config.rate_limits.get("pricing")
