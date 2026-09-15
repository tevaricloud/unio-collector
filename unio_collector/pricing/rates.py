from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.pricing.unit_rate import UnitRate


@dataclass(frozen=True)
class PricingRates:  # noqa: D101
    ebs_volume_gb_month: dict[tuple[str, str], UnitRate] = field(default_factory=dict)
    ebs_snapshot_gb_month: dict[str, UnitRate] = field(default_factory=dict)
    cloudwatch_logs_storage_gb_month: dict[str, UnitRate] = field(default_factory=dict)
    public_ipv4_hour: dict[str, UnitRate] = field(default_factory=dict)
    provider: str = "not_available"
    status: str = "not_loaded"
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    api_call_count: int = 0
    started_api_call_count: int = 0
    reserved_api_call_count: int = 0
    completed_api_call_count: int = 0
    failed_api_call_count: int = 0
    unfinished_api_call_count: int = 0
    lookup_request_count: int = 0
    scheduled_lookup_request_count: int = 0
    omitted_lookup_request_count: int = 0
    completed_lookup_request_count: int = 0
    stopped_lookup_request_count: int = 0
    observed_pages_per_lookup: float | None = None
    max_api_calls: int | None = None
    timeout_seconds: int | None = None
    api_call_timeout_seconds: int | None = None
    worker_count: int | None = None
    stop_reason: str | None = None
    budget_estimate: dict[str, Any] = field(default_factory=dict)
    lookup_diagnostics: list[dict[str, Any]] = field(default_factory=list)
    cache_hit_count: int = 0
    cache_miss_count: int = 0
    lookup_plan_summary: dict[str, Any] = field(default_factory=dict)
