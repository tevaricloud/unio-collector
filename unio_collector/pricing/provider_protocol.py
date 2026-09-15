from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.pricing.lookup.plan import PricingLookupPlan
    from unio_collector.pricing.progress import PricingRateProgress
    from unio_collector.pricing.rates import PricingRates


class PricingRateProvider(Protocol):  # noqa: D101
    def collect_rates(  # noqa: D102
        self,
        *,
        regions: set[str],
        ebs_volume_types: set[str],
        include_snapshots: bool = True,
        include_logs_storage: bool = True,
        include_public_ipv4: bool = True,
        lookup_plan: PricingLookupPlan | None = None,
        deadline_monotonic: float | None = None,
        max_api_calls: int | None = None,
        timeout_seconds: int | None = None,
        api_call_timeout_seconds: int | None = None,
        worker_count: int = 4,
        progress: PricingRateProgress | None = None,
    ) -> PricingRates: ...
