from __future__ import annotations  # noqa: D100

import json
import threading
import time
from typing import TYPE_CHECKING, Any

from unio_collector.pricing.enrich.utils import extract_on_demand_rate
from unio_collector.pricing.lookup.diagnostic import PricingLookupDiagnostic
from unio_collector.pricing.stops import PricingLookupStoppedError
from unio_collector.pricing.unit_rate import UnitRate  # noqa: TC001

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.pricing.lookup.request import PricingLookupRequest
    from unio_collector.pricing.progress import PricingRateProgress


class PricingApiProductFinder:  # noqa: D101
    def __init__(  # noqa: D107
        self,
        client: Any,  # noqa: ANN401
        *,
        deadline_monotonic: float | None = None,
        max_api_calls: int | None = None,
        api_call_timeout_seconds: int | None = None,
        progress: PricingRateProgress | None = None,
    ) -> None:
        self.client = client
        self.deadline_monotonic = deadline_monotonic
        self.max_api_calls = max_api_calls
        self.api_call_timeout_seconds = api_call_timeout_seconds
        self.progress = progress
        self.api_call_count = 0
        self._rate_cache: dict[tuple[str, str, str], UnitRate | None] = {}
        self._cache_lock = threading.Lock()
        self._call_lock = threading.Lock()

    def find_ec2_rate(  # noqa: D102
        self,
        *,
        location: str,
        predicate: Callable[[dict[str, Any], str, str], bool],
        lookup_key: str | None = None,
        filters: tuple[dict[str, str], ...] = (),
        lookup_request: PricingLookupRequest | None = None,
    ) -> UnitRate | None:
        return self.find_rate(
            service_code="AmazonEC2",
            location=location,
            predicate=predicate,
            lookup_key=lookup_key,
            filters=filters,
            lookup_request=lookup_request,
        )

    def find_cloudwatch_rate(  # noqa: D102
        self,
        *,
        location: str,
        predicate: Callable[[dict[str, Any], str, str], bool],
        lookup_key: str | None = None,
        filters: tuple[dict[str, str], ...] = (),
        lookup_request: PricingLookupRequest | None = None,
    ) -> UnitRate | None:
        return self.find_rate(
            service_code="AmazonCloudWatch",
            location=location,
            predicate=predicate,
            lookup_key=lookup_key,
            filters=filters,
            lookup_request=lookup_request,
        )

    def find_vpc_rate(  # noqa: D102
        self,
        *,
        location: str,
        predicate: Callable[[dict[str, Any], str, str], bool],
        lookup_key: str | None = None,
        filters: tuple[dict[str, str], ...] = (),
        lookup_request: PricingLookupRequest | None = None,
    ) -> UnitRate | None:
        return self.find_rate(
            service_code="AmazonVPC",
            location=location,
            predicate=predicate,
            lookup_key=lookup_key,
            filters=filters,
            lookup_request=lookup_request,
        )

    def find_rate(  # noqa: C901, D102
        self,
        *,
        service_code: str,
        location: str,
        predicate: Callable[[dict[str, Any], str, str], bool],
        lookup_key: str | None = None,
        filters: tuple[dict[str, str], ...] = (),
        lookup_request: PricingLookupRequest | None = None,
    ) -> UnitRate | None:
        cache_key = (
            (
                service_code,
                location,
                lookup_key,
            )
            if lookup_key
            else None
        )
        if cache_key is not None:
            cache_hit, cached = self._try_get_cached_rate(cache_key)
            if cache_hit:
                if self.progress:
                    self.progress.record_cache_hit()
                return cached
            if self.progress:
                self.progress.record_cache_miss()
        token: str | None = None
        page_count = 0
        product_count = 0
        try:
            while True:
                request: dict[str, Any] = {
                    "ServiceCode": service_code,
                    "Filters": [
                        {"Type": "TERM_MATCH", "Field": "location", "Value": location},
                        *filters,
                    ],
                    "MaxResults": 100,
                }
                if token:
                    request["NextToken"] = token
                self._reserve_api_call()
                try:
                    response = self.client.get_products(**request)
                except Exception as exc:
                    if self.progress:
                        self.progress.record_api_call_failed()
                        self.progress.record_lookup_request_stopped(
                            page_count,
                            diagnostic=self._build_diagnostic(
                                lookup_request=lookup_request,
                                service_code=service_code,
                                location=location,
                                lookup_key=lookup_key,
                                filters=filters,
                                status="failed",
                                page_count=page_count,
                                product_count=product_count,
                                matched=False,
                                error=str(exc),
                            ),
                        )
                    raise
                page_count += 1
                if self.progress:
                    self.progress.record_api_call_completed()
                price_list = response.get("PriceList", [])
                product_count += len(price_list)
                for raw_product in price_list:
                    product = json.loads(raw_product)
                    attributes = product.get("product", {}).get("attributes", {})
                    usage_type = str(attributes.get("usagetype") or "")
                    product_family = str(
                        product.get("product", {}).get("productFamily") or "",
                    )
                    if not predicate(attributes, usage_type, product_family):
                        continue
                    rate = extract_on_demand_rate(product)
                    if rate:
                        if cache_key is not None:
                            self._set_cached_rate(cache_key, rate)
                        if self.progress:
                            self.progress.record_lookup_request_completed(
                                page_count,
                                diagnostic=self._build_diagnostic(
                                    lookup_request=lookup_request,
                                    service_code=service_code,
                                    location=location,
                                    lookup_key=lookup_key,
                                    filters=filters,
                                    status="completed",
                                    page_count=page_count,
                                    product_count=product_count,
                                    matched=True,
                                ),
                            )
                        return rate
                token = response.get("NextToken")
                if not token:
                    if cache_key is not None:
                        self._set_cached_rate(cache_key, None)
                    if self.progress:
                        self.progress.record_lookup_request_completed(
                            page_count,
                            diagnostic=self._build_diagnostic(
                                lookup_request=lookup_request,
                                service_code=service_code,
                                location=location,
                                lookup_key=lookup_key,
                                filters=filters,
                                status="completed",
                                page_count=page_count,
                                product_count=product_count,
                                matched=False,
                            ),
                        )
                    return None
        except PricingLookupStoppedError as exc:
            if self.progress:
                self.progress.record_lookup_request_stopped(
                    page_count,
                    diagnostic=self._build_diagnostic(
                        lookup_request=lookup_request,
                        service_code=service_code,
                        location=location,
                        lookup_key=lookup_key,
                        filters=filters,
                        status="stopped",
                        page_count=page_count,
                        product_count=product_count,
                        matched=False,
                        error=str(exc),
                    ),
                )
            raise

    def _build_diagnostic(
        self,
        *,
        lookup_request: PricingLookupRequest | None,
        service_code: str,
        location: str,
        lookup_key: str | None,
        filters: tuple[dict[str, str], ...],
        status: str,
        page_count: int,
        product_count: int,
        matched: bool,
        error: str | None = None,
    ) -> PricingLookupDiagnostic:
        return PricingLookupDiagnostic(
            request_type=(lookup_request.request_type if lookup_request is not None else "unknown"),
            region=lookup_request.region if lookup_request is not None else "unknown",
            location=location,
            service_code=service_code,
            lookup_key=lookup_key,
            status=status,
            page_count=page_count,
            product_count=product_count,
            matched=matched,
            filters=filters,
            error=error,
        )

    def _try_get_cached_rate(
        self,
        cache_key: tuple[str, str, str],
    ) -> tuple[bool, UnitRate | None]:
        with self._cache_lock:
            if cache_key not in self._rate_cache:
                return False, None
            return True, self._rate_cache[cache_key]

    def _set_cached_rate(
        self,
        cache_key: tuple[str, str, str],
        rate: UnitRate | None,
    ) -> None:
        with self._cache_lock:
            self._rate_cache[cache_key] = rate

    def _reserve_api_call(self) -> None:
        with self._call_lock:
            self._ensure_lookup_allowed()
            self.api_call_count += 1
            if self.progress:
                self.progress.record_api_call_reserved()

    def _ensure_lookup_allowed(self) -> None:
        if self.deadline_monotonic is not None and time.monotonic() >= self.deadline_monotonic:
            msg = "Pricing lookup exceeded the configured timeout."
            raise PricingLookupStoppedError(
                msg,
                status="timed_out",
            )
        if (
            self.deadline_monotonic is not None
            and self.api_call_timeout_seconds is not None
            and self.deadline_monotonic - time.monotonic() <= self.api_call_timeout_seconds
        ):
            msg = "Pricing lookup stopped before starting another API call because the remaining budget was below the configured per-call timeout."
            raise PricingLookupStoppedError(
                msg,
                status="timed_out",
            )
        if self.max_api_calls is not None and self.api_call_count >= self.max_api_calls:
            msg = "Pricing lookup reached the configured AWS Price List API call limit."
            raise PricingLookupStoppedError(
                msg,
                status="api_call_limit_reached",
            )
