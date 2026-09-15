from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.platform_inventory import (
    ManagedPlatformInventoryCollector,
    normalize_api_gateway_vpc_link_detail_mode,
    normalize_ecs_regional_collection_mode,
    normalize_ecs_task_definition_detail_mode,
    normalize_elasticache_metric_detail_mode,
)
from unio_collector.scanners.cost_context import enrich_records_with_cost_context
from unio_collector.scanners.platform.managed.types import (
    PLATFORM_COST_EXPLORER_SERVICE_NAMES,
    ManagedPlatformRecord,
    TManagedPlatformRecord,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from unio_collector.aws.cost_explorer import DailyCostRecord
    from unio_collector.scanners.base import ScannerContext


def build_managed_platform_collector(  # noqa: D103
    context: ScannerContext,
    *,
    selected_regions: list[str] | None = None,
) -> ManagedPlatformInventoryCollector:
    scanner_id = context.definition.scanner_id
    return ManagedPlatformInventoryCollector(
        context.security.session,
        account_id=context.security.account_id,
        audit_context=context.security.create_audit_context(
            "ManagedPlatformInventoryCollector",
        ),
        selected_regions=(selected_regions if selected_regions is not None else context.options.get_selected_regions()),
        api_gateway_vpc_link_detail_mode=normalize_api_gateway_vpc_link_detail_mode(
            context.options.get_for_scanner(
                scanner_id,
                "vpc_link_detail_mode",
                "full",
            ),
        ),
        ecs_task_definition_detail_mode=normalize_ecs_task_definition_detail_mode(
            context.options.get_for_scanner(
                scanner_id,
                "task_definition_detail_mode",
                "full",
            ),
        ),
        ecs_regional_collection_mode=normalize_ecs_regional_collection_mode(
            context.options.get_for_scanner(
                scanner_id,
                "regional_collection_mode",
                "full",
            ),
        ),
        elasticache_metric_detail_mode=normalize_elasticache_metric_detail_mode(
            context.options.get_for_scanner(
                scanner_id,
                "metric_detail_mode",
                "full",
            ),
        ),
    )


def add_managed_platform_cost_context(  # noqa: D103
    records: list[TManagedPlatformRecord],
    context: ScannerContext,
    *,
    regional_costs: list[DailyCostRecord] | None = None,
) -> list[TManagedPlatformRecord]:
    service_names = PLATFORM_COST_EXPLORER_SERVICE_NAMES.get(
        context.definition.scanner_id,
        (),
    )
    if not records or not service_names:
        return records
    try:
        service_costs = context.costs.collect_service_costs()
        if regional_costs is None:
            regional_costs = collect_managed_platform_regional_costs(context)
    except Exception as exc:  # noqa: BLE001
        code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
        context.warnings.add(
            (f"Cost Explorer context was unavailable for this managed-platform scanner; metadata findings continued ({code})."),
        )
        return records
    return enrich_records_with_cost_context(
        records,
        service_names=service_names,
        service_costs=service_costs,
        daily_costs=regional_costs,
    )


def collect_managed_platform_regional_costs(  # noqa: D103
    context: ScannerContext,
) -> list[DailyCostRecord]:
    return context.costs.collect_daily_costs(
        group_keys=("SERVICE", "REGION"),
    )


def record_managed_platform_execution_detail(  # noqa: D103
    context: ScannerContext,
    records: Sequence[ManagedPlatformRecord],
    *,
    regions: Sequence[str],
    service_label: str,
    resource_label: str,
    resource_count: int,
    detail_counts: dict[str, int],
) -> None:
    context.warnings.add_coverage_note(
        build_managed_platform_execution_detail_note(
            records,
            scanner_id=context.definition.scanner_id,
            regions=regions,
            service_label=service_label,
            resource_label=resource_label,
            resource_count=resource_count,
            detail_counts=detail_counts,
        ),
    )


def build_managed_platform_execution_detail_note(  # noqa: D103
    records: Sequence[ManagedPlatformRecord],
    *,
    scanner_id: str,
    regions: Sequence[str],
    service_label: str,
    resource_label: str,
    resource_count: int,
    detail_counts: dict[str, int],
) -> dict[str, Any]:
    region_record_count = len(records)
    cost_context_record_count = sum(1 for record in records if has_cost_context(record))
    permission_error_count = sum(len(record.permission_errors) for record in records)
    billing_context_summary = build_managed_platform_billing_context_summary(
        cost_context_record_count,
    )
    return {
        "note_type": "execution_detail",
        "scanner_id": scanner_id,
        "scope_area": "managed_platform_metadata",
        "summary": (
            f"{service_label} cost review collected {resource_count} "
            f"{resource_label}(s) across {region_record_count} region record(s); "
            f"{billing_context_summary}."
        ),
        "regions_attempted": list(regions),
        "region_record_count": region_record_count,
        "resource_label": resource_label,
        "resource_count": resource_count,
        "detail_counts": {key: value for key, value in detail_counts.items() if value is not None},
        "cost_context_record_count": cost_context_record_count,
        "permission_error_count": permission_error_count,
        "result_scope": "current_scan",
        "impact": ("This is read-only metadata and billing-context coverage evidence; it does not change AWS resources."),
    }


def build_managed_platform_billing_context_summary(  # noqa: D103
    cost_context_record_count: int,
) -> str:
    if cost_context_record_count <= 0:
        return "no matching service or regional billing context was attached to the collected metadata"
    return f"service or regional billing context was available on {cost_context_record_count} record(s); this is not resource-level cost attribution"


def has_cost_context(record: ManagedPlatformRecord) -> bool:  # noqa: D103
    return record.service_current_cost is not None or record.regional_current_cost is not None or record.regional_cost_record_count > 0
