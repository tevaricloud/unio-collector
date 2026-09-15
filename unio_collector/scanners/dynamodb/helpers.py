from __future__ import annotations  # noqa: D100

from dataclasses import replace
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from unio_collector.aws.dynamodb import (
    DynamoDbInventoryCollector,
    DynamoDbRegionRecord,
    normalize_dynamodb_autoscaling_detail_mode,
    normalize_dynamodb_metric_detail_mode,
    normalize_dynamodb_retention_detail_mode,
)
from unio_collector.pricing.enrich.constants import REGION_LOCATION_NAMES
from unio_collector.scanners.options import parse_scanner_option_int

if TYPE_CHECKING:
    from unio_collector.aws.cost_explorer import CostExplorerResult, DailyCostRecord
    from unio_collector.scanners.base import ScannerContext

DYNAMODB_COST_EXPLORER_SERVICE_NAME = "Amazon DynamoDB"


def build_dynamodb_collector(  # noqa: D103
    context: ScannerContext,
    *,
    table_detail_regions: list[str] | None = None,
) -> DynamoDbInventoryCollector:
    max_table_workers = parse_scanner_option_int(
        context.options.get(
            "max_table_workers",
            0,
        ),
    )
    retention_detail_mode = normalize_dynamodb_retention_detail_mode(
        context.options.get(
            "retention_detail_mode",
            "full",
        ),
    )
    metric_detail_mode = normalize_dynamodb_metric_detail_mode(
        context.options.get(
            "metric_detail_mode",
            "full",
        ),
    )
    autoscaling_detail_mode = normalize_dynamodb_autoscaling_detail_mode(
        context.options.get(
            "autoscaling_detail_mode",
            "full",
        ),
    )
    return DynamoDbInventoryCollector(
        context.security.session,
        account_id=context.security.account_id,
        audit_context=context.security.create_audit_context(
            "DynamoDbInventoryCollector",
        ),
        selected_regions=context.options.get_selected_regions(),
        max_table_workers=max_table_workers or None,
        retention_detail_mode=retention_detail_mode,
        metric_detail_mode=metric_detail_mode,
        autoscaling_detail_mode=autoscaling_detail_mode,
        table_detail_regions=table_detail_regions,
    )


def enrich_dynamodb_records_with_cost_context(  # noqa: D103
    records: list[DynamoDbRegionRecord],
    *,
    service_costs: CostExplorerResult,
    daily_costs: list[DailyCostRecord],
) -> list[DynamoDbRegionRecord]:
    service_context = get_dynamodb_service_cost_context(service_costs)
    regional_context = get_dynamodb_regional_cost_context(daily_costs)
    enriched: list[DynamoDbRegionRecord] = []
    for record in records:
        regional = regional_context.get(record.region)
        enriched.append(
            replace(
                record,
                service_current_cost=service_context.get("current_cost"),
                service_previous_cost=service_context.get("previous_cost"),
                service_cost_currency=service_context.get("currency"),
                regional_current_cost=(regional.get("current_cost") if regional is not None else None),
                regional_cost_currency=(regional.get("currency") if regional is not None else service_context.get("currency")),
                regional_cost_record_count=(int(regional.get("record_count") or 0) if regional is not None else 0),
            ),
        )
    return enriched


def get_dynamodb_service_cost_context(  # noqa: D103
    service_costs: CostExplorerResult,
) -> dict[str, Any]:
    for item in service_costs.service_costs:
        if not is_dynamodb_cost_service(item.get("service_name")):
            continue
        return {
            "current_cost": parse_decimal(item.get("current_cost")),
            "previous_cost": parse_decimal(item.get("previous_cost")),
            "currency": str(item.get("currency") or "USD"),
        }
    return {}


def get_dynamodb_regional_cost_context(  # noqa: D103
    daily_costs: list[DailyCostRecord],
) -> dict[str, dict[str, Any]]:
    totals: dict[str, dict[str, Any]] = {}
    for record in daily_costs:
        if not is_dynamodb_cost_service(record.service_name):
            continue
        region = resolve_cost_explorer_region(record.region)
        if not region:
            continue
        current = totals.setdefault(
            region,
            {
                "current_cost": Decimal(0),
                "currency": record.currency,
                "record_count": 0,
            },
        )
        current["current_cost"] = current["current_cost"] + record.cost
        current["currency"] = record.currency or current["currency"]
        current["record_count"] = int(current["record_count"]) + 1
    return totals


def is_dynamodb_cost_service(value: Any) -> bool:  # noqa: ANN401, D103
    return str(value or "").strip().lower() == (DYNAMODB_COST_EXPLORER_SERVICE_NAME.lower())


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
