"""Typed serialization contract for deterministic offline pricing replay."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from pydantic import Field, model_validator

from unio_collector.core.base_model import UnioBaseModel
from unio_collector.pricing.rates import PricingRates
from unio_collector.pricing.replay.unit_rate import PricingUnitRateRecord
from unio_collector.pricing.replay.usage import PricingUsageRecord
from unio_collector.pricing.unit_rate import UnitRate

if TYPE_CHECKING:
    from unio_collector.aws.daily_cost_record import DailyCostRecord

PRICING_CONTEXT_FILE = "scan-result/pricing-context.json"


class PricingReplayContext(UnioBaseModel):
    """Typed, offline-safe inputs for deterministic pricing enrichment."""

    schema_version: Literal["2026-01"] = "2026-01"
    status: str
    provider: str
    rates: list[PricingUnitRateRecord] = Field(default_factory=list)
    usage_records: list[PricingUsageRecord] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    api_call_count: int = 0
    started_api_call_count: int = 0
    reserved_api_call_count: int = 0
    completed_api_call_count: int = 0
    failed_api_call_count: int = 0
    unfinished_api_call_count: int = 0
    cache_hit_count: int = 0
    cache_miss_count: int = 0
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
    budget_estimate: dict[str, Any] = Field(default_factory=dict)
    lookup_diagnostics: list[dict[str, Any]] = Field(default_factory=list)
    lookup_plan_summary: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_unique_inputs(self) -> PricingReplayContext:
        """Reject ambiguous rate and usage identities."""
        rate_keys = [(item.rate_type, item.region, item.resource_variant) for item in self.rates]
        if len(rate_keys) != len(set(rate_keys)):
            msg = "Pricing replay context contains duplicate unit-rate identities."
            raise ValueError(msg)
        usage_keys = [(item.date, item.service_name, item.region, item.usage_type, item.currency) for item in self.usage_records]
        if len(usage_keys) != len(set(usage_keys)):
            msg = "Pricing replay context contains conflicting Cost Explorer usage identities."
            raise ValueError(msg)
        planned_lookups = int(
            self.lookup_plan_summary.get("targeted_lookup_request_count", 0),
        )
        if self.status in {"loaded", "partial"} and planned_lookups and not self.rates:
            msg = "Complete pricing replay context declares lookups but contains no rates."
            raise ValueError(msg)
        return self

    @classmethod
    def from_runtime(
        cls,
        rates: PricingRates,
        usage_records: list[DailyCostRecord],
        *,
        limitations: list[str] | None = None,
    ) -> PricingReplayContext:
        """Build a deterministic context from runtime inputs."""
        records: list[PricingUnitRateRecord] = []
        for (region, variant), rate in sorted(rates.ebs_volume_gb_month.items()):
            records.append(cls._rate_record("ebs_volume_gb_month", region, rate, variant))
        for region, rate in sorted(rates.ebs_snapshot_gb_month.items()):
            records.append(cls._rate_record("ebs_snapshot_gb_month", region, rate))
        for region, rate in sorted(rates.cloudwatch_logs_storage_gb_month.items()):
            records.append(cls._rate_record("cloudwatch_logs_storage_gb_month", region, rate))
        for region, rate in sorted(rates.public_ipv4_hour.items()):
            records.append(cls._rate_record("public_ipv4_hour", region, rate))
        metadata = {
            name: getattr(rates, name)
            for name in (
                "status",
                "provider",
                "errors",
                "warnings",
                "api_call_count",
                "started_api_call_count",
                "reserved_api_call_count",
                "completed_api_call_count",
                "failed_api_call_count",
                "unfinished_api_call_count",
                "lookup_request_count",
                "cache_hit_count",
                "cache_miss_count",
                "scheduled_lookup_request_count",
                "omitted_lookup_request_count",
                "completed_lookup_request_count",
                "stopped_lookup_request_count",
                "observed_pages_per_lookup",
                "max_api_calls",
                "timeout_seconds",
                "api_call_timeout_seconds",
                "worker_count",
                "stop_reason",
                "budget_estimate",
                "lookup_diagnostics",
                "lookup_plan_summary",
            )
        }
        ordered_usage = sorted(
            usage_records,
            key=lambda item: (item.date, item.service_name, item.region, item.usage_type or "", item.currency),
        )
        return cls(
            **metadata,
            rates=records,
            usage_records=[PricingUsageRecord.model_validate(item.__dict__) for item in ordered_usage],
            limitations=list(limitations or []),
        )

    @staticmethod
    def _rate_record(
        rate_type: str,
        region: str,
        rate: UnitRate,
        variant: str | None = None,
    ) -> PricingUnitRateRecord:
        return PricingUnitRateRecord(
            rate_type=rate_type,  # type: ignore[arg-type]
            region=region,
            resource_variant=variant,
            amount=rate.amount,
            currency=rate.currency,
            unit=rate.unit,
            source=rate.source,
        )

    def to_pricing_rates(self) -> PricingRates:
        """Reconstruct the exact runtime rates."""
        volume: dict[tuple[str, str], UnitRate] = {}
        snapshot: dict[str, UnitRate] = {}
        logs: dict[str, UnitRate] = {}
        ipv4: dict[str, UnitRate] = {}
        targets: dict[str, dict[Any, UnitRate]] = {
            "ebs_snapshot_gb_month": snapshot,
            "cloudwatch_logs_storage_gb_month": logs,
            "public_ipv4_hour": ipv4,
        }
        for record in self.rates:
            rate = UnitRate(record.amount, record.currency, record.unit, record.source)
            if record.rate_type == "ebs_volume_gb_month":
                if not record.resource_variant:
                    msg = "EBS volume pricing rate is missing resource_variant."
                    raise ValueError(msg)
                volume[(record.region, record.resource_variant)] = rate
            else:
                targets[record.rate_type][record.region] = rate
        metadata = self.model_dump(exclude={"schema_version", "rates", "usage_records", "limitations"})
        return PricingRates(
            **metadata,
            ebs_volume_gb_month=volume,
            ebs_snapshot_gb_month=snapshot,
            cloudwatch_logs_storage_gb_month=logs,
            public_ipv4_hour=ipv4,
        )

    def to_daily_cost_records(self) -> list[DailyCostRecord]:
        """Reconstruct Cost Explorer usage inputs."""
        return [record.to_daily_cost_record() for record in self.usage_records]
