from __future__ import annotations  # noqa: D100

import threading
from typing import Any

from unio_collector.pricing.lookup.budget_estimate import PricingLookupBudgetEstimate  # noqa: TC001
from unio_collector.pricing.lookup.diagnostic import PricingLookupDiagnostic  # noqa: TC001
from unio_collector.pricing.rates import PricingRates
from unio_collector.pricing.stops import is_expected_pricing_stop
from unio_collector.pricing.unit_rate import UnitRate  # noqa: TC001


class PricingRateProgress:  # noqa: D101
    def __init__(  # noqa: D107
        self,
        *,
        provider: str = "aws-price-list-query-api",
        max_api_calls: int | None = None,
        timeout_seconds: int | None = None,
        api_call_timeout_seconds: int | None = None,
        worker_count: int | None = None,
    ) -> None:
        self.provider = provider
        self.max_api_calls = max_api_calls
        self.timeout_seconds = timeout_seconds
        self.api_call_timeout_seconds = api_call_timeout_seconds
        self.worker_count = worker_count
        self._lock = threading.Lock()
        self._reserved_api_call_count = 0
        self._completed_api_call_count = 0
        self._failed_api_call_count = 0
        self._lookup_request_count = 0
        self._scheduled_lookup_request_count = 0
        self._omitted_lookup_request_count = 0
        self._completed_lookup_request_count = 0
        self._stopped_lookup_request_count = 0
        self._lookup_page_counts: list[int] = []
        self._lookup_diagnostics: list[PricingLookupDiagnostic] = []
        self._budget_estimate: dict[str, Any] = {}
        self._lookup_plan_summary: dict[str, Any] = {}
        self._cache_hit_count = 0
        self._cache_miss_count = 0
        self._ebs_volume_rates: dict[tuple[str, str], UnitRate] = {}
        self._snapshot_rates: dict[str, UnitRate] = {}
        self._logs_storage_rates: dict[str, UnitRate] = {}
        self._public_ipv4_rates: dict[str, UnitRate] = {}
        self._errors: list[str] = []
        self._warnings: list[str] = []
        self._stop_reason: str | None = None

    def record_api_call(self) -> None:  # noqa: D102
        with self._lock:
            self._reserved_api_call_count += 1
            self._completed_api_call_count += 1

    def record_api_call_reserved(self) -> None:  # noqa: D102
        with self._lock:
            self._reserved_api_call_count += 1

    def record_api_call_completed(self) -> None:  # noqa: D102
        with self._lock:
            self._completed_api_call_count += 1

    def record_api_call_failed(self) -> None:  # noqa: D102
        with self._lock:
            self._failed_api_call_count += 1

    def record_lookup_schedule(  # noqa: D102
        self,
        *,
        lookup_request_count: int,
        scheduled_lookup_request_count: int,
        omitted_lookup_request_count: int,
    ) -> None:
        with self._lock:
            self._lookup_request_count = lookup_request_count
            self._scheduled_lookup_request_count = scheduled_lookup_request_count
            self._omitted_lookup_request_count = omitted_lookup_request_count

    def record_lookup_request_completed(  # noqa: D102
        self,
        page_count: int,
        *,
        diagnostic: PricingLookupDiagnostic | None = None,
    ) -> None:
        with self._lock:
            self._completed_lookup_request_count += 1
            self._lookup_page_counts.append(max(0, page_count))
            if diagnostic:
                self._lookup_diagnostics.append(diagnostic)

    def record_lookup_request_stopped(  # noqa: D102
        self,
        page_count: int,
        *,
        diagnostic: PricingLookupDiagnostic | None = None,
    ) -> None:
        with self._lock:
            self._stopped_lookup_request_count += 1
            if page_count > 0:
                self._lookup_page_counts.append(page_count)
            if diagnostic:
                self._lookup_diagnostics.append(diagnostic)

    def record_budget_estimate(  # noqa: D102
        self,
        estimate: PricingLookupBudgetEstimate,
    ) -> None:
        with self._lock:
            self._budget_estimate = estimate.convert_to_dict()

    def record_lookup_plan_summary(self, summary: dict[str, Any]) -> None:  # noqa: D102
        with self._lock:
            self._lookup_plan_summary = dict(summary)

    def record_cache_hit(self) -> None:  # noqa: D102
        with self._lock:
            self._cache_hit_count += 1

    def record_cache_miss(self) -> None:  # noqa: D102
        with self._lock:
            self._cache_miss_count += 1

    def record_ebs_volume_rate(  # noqa: D102
        self,
        region: str,
        volume_type: str,
        rate: UnitRate,
    ) -> None:
        with self._lock:
            self._ebs_volume_rates[(region, volume_type)] = rate

    def record_snapshot_rate(self, region: str, rate: UnitRate) -> None:  # noqa: D102
        with self._lock:
            self._snapshot_rates[region] = rate

    def record_logs_storage_rate(self, region: str, rate: UnitRate) -> None:  # noqa: D102
        with self._lock:
            self._logs_storage_rates[region] = rate

    def record_public_ipv4_rate(self, region: str, rate: UnitRate) -> None:  # noqa: D102
        with self._lock:
            self._public_ipv4_rates[region] = rate

    def record_stop(self, reason: str, message: str | None = None) -> None:  # noqa: D102
        with self._lock:
            self._stop_reason = reason
            if message:
                if is_expected_pricing_stop(reason):
                    self._warnings.append(message)
                else:
                    self._errors.append(message)

    def record_error(self, message: str) -> None:  # noqa: D102
        with self._lock:
            self._errors.append(message)

    def record_warning(self, message: str) -> None:  # noqa: D102
        with self._lock:
            self._warnings.append(message)

    def has_rates(self) -> bool:  # noqa: D102
        with self._lock:
            return any(
                (
                    self._ebs_volume_rates,
                    self._snapshot_rates,
                    self._logs_storage_rates,
                    self._public_ipv4_rates,
                ),
            )

    def build_rates(  # noqa: D102
        self,
        *,
        status: str | None = None,
        stop_reason: str | None = None,
        errors: list[str] | None = None,
        warnings: list[str] | None = None,
    ) -> PricingRates:
        with self._lock:
            loaded_any = any(
                (
                    self._ebs_volume_rates,
                    self._snapshot_rates,
                    self._logs_storage_rates,
                    self._public_ipv4_rates,
                ),
            )
            effective_status = status or ("loaded" if loaded_any else "empty")
            effective_stop_reason = stop_reason or self._stop_reason
            combined_errors: list[str] = []
            for error in [*self._errors, *(errors or [])]:
                if error not in combined_errors:
                    combined_errors.append(error)
            combined_warnings: list[str] = []
            for warning in [*self._warnings, *(warnings or [])]:
                if warning not in combined_warnings:
                    combined_warnings.append(warning)
            unfinished_api_calls = max(
                0,
                self._reserved_api_call_count - self._completed_api_call_count - self._failed_api_call_count,
            )
            observed_pages_per_lookup = (
                round(
                    sum(self._lookup_page_counts) / len(self._lookup_page_counts),
                    2,
                )
                if self._lookup_page_counts
                else None
            )
            return PricingRates(
                ebs_volume_gb_month=dict(self._ebs_volume_rates),
                ebs_snapshot_gb_month=dict(self._snapshot_rates),
                cloudwatch_logs_storage_gb_month=dict(self._logs_storage_rates),
                public_ipv4_hour=dict(self._public_ipv4_rates),
                provider=self.provider,
                status=effective_status,
                errors=combined_errors,
                warnings=combined_warnings,
                api_call_count=(self._completed_api_call_count + self._failed_api_call_count),
                started_api_call_count=self._reserved_api_call_count,
                reserved_api_call_count=self._reserved_api_call_count,
                completed_api_call_count=self._completed_api_call_count,
                failed_api_call_count=self._failed_api_call_count,
                unfinished_api_call_count=unfinished_api_calls,
                lookup_request_count=self._lookup_request_count,
                scheduled_lookup_request_count=self._scheduled_lookup_request_count,
                omitted_lookup_request_count=self._omitted_lookup_request_count,
                completed_lookup_request_count=self._completed_lookup_request_count,
                stopped_lookup_request_count=self._stopped_lookup_request_count,
                observed_pages_per_lookup=observed_pages_per_lookup,
                max_api_calls=self.max_api_calls,
                timeout_seconds=self.timeout_seconds,
                api_call_timeout_seconds=self.api_call_timeout_seconds,
                worker_count=self.worker_count,
                stop_reason=effective_stop_reason,
                budget_estimate=dict(self._budget_estimate),
                lookup_diagnostics=[item.convert_to_dict() for item in self._lookup_diagnostics],
                cache_hit_count=self._cache_hit_count,
                cache_miss_count=self._cache_miss_count,
                lookup_plan_summary=dict(self._lookup_plan_summary),
            )
