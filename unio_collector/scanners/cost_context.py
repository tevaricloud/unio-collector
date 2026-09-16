from __future__ import annotations  # noqa: D100

from dataclasses import replace
from decimal import Decimal
from typing import TYPE_CHECKING, Any, cast

from unio_collector.aws.cost_explorer import (
    CostExplorerResult,
    DailyCostRecord,
    UsageTypeCostSummary,
)
from unio_collector.pricing.enrich.constants import REGION_LOCATION_NAMES
from unio_collector.scanners.regional.cost_context import RegionalCostContext
from unio_collector.scanners.service.cost_context import ServiceCostContext

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


def enrich_records_with_cost_context[T](  # noqa: D103
    records: Sequence[T],
    *,
    service_names: Iterable[str],
    service_costs: CostExplorerResult,
    daily_costs: Sequence[DailyCostRecord],
    usage_type_costs: Sequence[DailyCostRecord] = (),
    usage_type_limit: int = 5,
) -> list[T]:
    service_context = get_service_cost_context(
        service_costs,
        service_names=service_names,
    )
    regional_context = get_regional_cost_context(
        daily_costs,
        service_names=service_names,
    )
    usage_type_context = get_usage_type_cost_context(
        usage_type_costs,
        service_names=service_names,
        limit=usage_type_limit,
    )
    enriched: list[T] = []
    for record in records:
        region = str(getattr(record, "region", "") or "")
        regional = regional_context.get(region)
        replacements: dict[str, object] = {
            "service_current_cost": service_context.current_cost,
            "service_previous_cost": service_context.previous_cost,
            "service_cost_currency": service_context.currency,
            "regional_current_cost": (regional.current_cost if regional is not None else None),
            "regional_cost_currency": (regional.currency if regional is not None else service_context.currency),
            "regional_cost_record_count": (regional.record_count if regional is not None else 0),
        }
        if hasattr(record, "top_usage_type_costs"):
            replacements["top_usage_type_costs"] = usage_type_context
        enriched.append(
            cast(
                "T",
                replace(
                    cast("Any", record),
                    **replacements,
                ),
            ),
        )
    return enriched


def get_service_cost_context(  # noqa: D103
    service_costs: CostExplorerResult,
    *,
    service_names: Iterable[str],
) -> ServiceCostContext:
    normalized_names = normalize_service_names(service_names)
    current_cost = Decimal(0)
    previous_cost = Decimal(0)
    currency: str | None = None
    matched = False
    for item in service_costs.service_costs:
        if normalize_service_name(item.get("service_name")) not in normalized_names:
            continue
        matched = True
        current_cost += parse_decimal(item.get("current_cost"))
        previous_cost += parse_decimal(item.get("previous_cost"))
        if currency is None:
            currency = str(item.get("currency") or "USD")
    if not matched:
        return ServiceCostContext()
    return ServiceCostContext(
        current_cost=current_cost,
        previous_cost=previous_cost,
        currency=currency or "USD",
    )


def get_regional_cost_context(  # noqa: D103
    daily_costs: Sequence[DailyCostRecord],
    *,
    service_names: Iterable[str],
) -> dict[str, RegionalCostContext]:
    normalized_names = normalize_service_names(service_names)
    totals: dict[str, RegionalCostContext] = {}
    for record in daily_costs:
        if normalize_service_name(record.service_name) not in normalized_names:
            continue
        region = resolve_cost_explorer_region(record.region)
        if not region:
            continue
        current = totals.get(region, RegionalCostContext(currency=record.currency))
        totals[region] = RegionalCostContext(
            current_cost=current.current_cost + record.cost,
            currency=record.currency or current.currency,
            record_count=current.record_count + 1,
        )
    return totals


def get_usage_type_cost_context(  # noqa: D103
    daily_costs: Sequence[DailyCostRecord],
    *,
    service_names: Iterable[str],
    limit: int = 5,
) -> list[UsageTypeCostSummary]:
    normalized_names = normalize_service_names(service_names)
    totals: dict[str, UsageTypeCostSummary] = {}
    for record in daily_costs:
        if normalize_service_name(record.service_name) not in normalized_names:
            continue
        usage_type = str(record.usage_type or "").strip()
        if not usage_type:
            continue
        current = totals.get(
            usage_type,
            UsageTypeCostSummary(
                usage_type=usage_type,
                current_cost=Decimal(0),
                currency=record.currency or "USD",
            ),
        )
        totals[usage_type] = UsageTypeCostSummary(
            usage_type=usage_type,
            current_cost=current.current_cost + record.cost,
            currency=record.currency or current.currency,
            record_count=current.record_count + 1,
        )
    return sorted(
        totals.values(),
        key=lambda item: item.current_cost,
        reverse=True,
    )[: max(limit, 0)]


def normalize_service_names(service_names: Iterable[str]) -> set[str]:  # noqa: D103
    return {normalized for service_name in service_names if (normalized := normalize_service_name(service_name))}


def normalize_service_name(value: Any) -> str:  # noqa: ANN401, D103
    return str(value or "").strip().lower()


def resolve_cost_explorer_region(value: Any) -> str | None:  # noqa: ANN401, D103
    raw = str(value or "").strip()
    if not raw:
        return None
    normalized = raw.lower()
    for region, location in REGION_LOCATION_NAMES.items():
        if normalized in {region.lower(), location.lower()}:
            return region
    if normalized.startswith(("us-", "eu-", "ap-", "ca-", "sa-", "af-", "me-")):
        return raw
    return None


def parse_decimal(value: Any) -> Decimal:  # noqa: ANN401, D103
    try:
        return Decimal(str(value or "0"))
    except Exception:  # noqa: BLE001
        return Decimal(0)
