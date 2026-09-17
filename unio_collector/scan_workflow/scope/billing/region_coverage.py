from __future__ import annotations  # noqa: D100

import re
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from unio_collector.scan_workflow.scope.billing.coverage_payload import (
    BillingRegionCoveragePayload,
)

if TYPE_CHECKING:
    from unio_collector.aws.cost_explorer import DailyCostRecord
    from unio_collector.core.cost_period import CostPeriod

AWS_REGION_PATTERN = re.compile(
    r"^(?:af|ap|ca|eu|il|me|mx|sa|us|us-gov)-"
    r"(?:central|north|south|east|west|northeast|southeast|southwest|northwest)-\d$",
)
GLOBAL_REGION_VALUES = {
    "",
    "global",
    "no region",
    "noregion",
    "no-region",
    "not applicable",
    "not recorded",
    "unknown",
}
DEFAULT_MATERIALITY_THRESHOLD = Decimal("0.01")


class BillingRegionCoverageBuilder:
    """Build billing-region scope coverage from Cost Explorer evidence."""

    def build_from_daily_costs(
        self,
        records: list[DailyCostRecord],
        *,
        selected_regions: list[str],
        explicit_region_scope: bool,
        current_period: CostPeriod,
        limitations: list[str] | None = None,
        materiality_threshold: Decimal = DEFAULT_MATERIALITY_THRESHOLD,
    ) -> BillingRegionCoveragePayload:
        """Build region coverage from daily Cost Explorer records."""
        region_costs: dict[str, Decimal] = {}
        global_or_unallocated_cost = Decimal(0)
        currency = current_period.currency
        unknown_values: set[str] = set()
        for record in records:
            if record.cost <= 0:
                continue
            normalized_region = normalize_billing_region(record.region)
            if normalized_region is None:
                global_or_unallocated_cost += record.cost
                continue
            if normalized_region == "unknown":
                unknown_values.add(record.region)
                global_or_unallocated_cost += record.cost
                continue
            currency = record.currency or currency
            region_costs[normalized_region] = region_costs.get(normalized_region, Decimal(0)) + record.cost
        active_limitations = list(limitations or [])
        if unknown_values:
            active_limitations.append(
                "Cost Explorer returned region dimension values that were not "
                "recognized as AWS regions and were treated as global or "
                f"unallocated billing scope: {', '.join(sorted(unknown_values))}.",
            )
        return self._build_payload(
            status="available",
            selected_regions=selected_regions,
            explicit_region_scope=explicit_region_scope,
            current_period=current_period,
            currency=currency,
            region_costs=region_costs,
            global_or_unallocated_cost=global_or_unallocated_cost,
            limitations=active_limitations,
            materiality_threshold=materiality_threshold,
            unrecognized_region_values=sorted(unknown_values),
        )

    def build_from_service_costs(
        self,
        service_costs: list[dict[str, Any]],
        *,
        selected_regions: list[str],
        explicit_region_scope: bool,
        current_period: CostPeriod,
        currency: str,
        limitations: list[str] | None = None,
        materiality_threshold: Decimal = DEFAULT_MATERIALITY_THRESHOLD,
    ) -> BillingRegionCoveragePayload:
        """Build region coverage from fixture service-cost rows."""
        region_costs: dict[str, Decimal] = {}
        global_or_unallocated_cost = Decimal(0)
        unknown_values: set[str] = set()
        for item in service_costs:
            cost = parse_decimal(item.get("current_cost"))
            if cost <= 0:
                continue
            raw_region = str(item.get("region") or "global")
            normalized_region = normalize_billing_region(raw_region)
            if normalized_region is None:
                global_or_unallocated_cost += cost
                continue
            if normalized_region == "unknown":
                unknown_values.add(raw_region)
                global_or_unallocated_cost += cost
                continue
            region_costs[normalized_region] = region_costs.get(normalized_region, Decimal(0)) + cost
        active_limitations = list(limitations or [])
        if unknown_values:
            active_limitations.append(
                f"Fixture service cost rows included non-region billing scope values: {', '.join(sorted(unknown_values))}.",
            )
        return self._build_payload(
            status="available",
            selected_regions=selected_regions,
            explicit_region_scope=explicit_region_scope,
            current_period=current_period,
            currency=currency,
            region_costs=region_costs,
            global_or_unallocated_cost=global_or_unallocated_cost,
            limitations=active_limitations,
            materiality_threshold=materiality_threshold,
            unrecognized_region_values=sorted(unknown_values),
        )

    def build_unavailable(
        self,
        *,
        selected_regions: list[str],
        explicit_region_scope: bool,
        current_period: CostPeriod,
        currency: str,
        reason: str,
        materiality_threshold: Decimal = DEFAULT_MATERIALITY_THRESHOLD,
    ) -> BillingRegionCoveragePayload:
        """Build an unavailable coverage payload with a limitation reason."""
        return self._build_payload(
            status="unavailable",
            selected_regions=selected_regions,
            explicit_region_scope=explicit_region_scope,
            current_period=current_period,
            currency=currency,
            region_costs={},
            global_or_unallocated_cost=Decimal(0),
            limitations=[reason],
            materiality_threshold=materiality_threshold,
            unrecognized_region_values=[],
        )

    def _build_payload(
        self,
        *,
        status: str,
        selected_regions: list[str],
        explicit_region_scope: bool,
        current_period: CostPeriod,
        currency: str,
        region_costs: dict[str, Decimal],
        global_or_unallocated_cost: Decimal,
        limitations: list[str],
        materiality_threshold: Decimal,
        unrecognized_region_values: list[str],
    ) -> BillingRegionCoveragePayload:
        selected = sorted(dict.fromkeys(selected_regions))
        active_regions = sorted(region for region, cost in region_costs.items() if cost > 0)
        outside_scan = [region for region in active_regions if explicit_region_scope and region not in selected]
        material_regions = [region for region in active_regions if region_costs[region] >= materiality_threshold]
        residual_regions = [region for region in active_regions if Decimal(0) < region_costs[region] < materiality_threshold]
        material_outside_scan = [region for region in outside_scan if region in material_regions]
        residual_outside_scan = [region for region in outside_scan if region in residual_regions]
        region_records = [
            {
                "region": region,
                "current_cost": str(region_costs[region]),
                "currency": currency,
                "selected_for_scan": region in selected,
                "material": region_costs[region] >= materiality_threshold,
                "outside_selected_scan_scope": region in outside_scan,
            }
            for region in active_regions
        ]
        notice_severity = "none"
        if material_outside_scan:
            notice_severity = "warning"
        elif residual_outside_scan:
            notice_severity = "info"
        material_warning_required = bool(
            explicit_region_scope and material_outside_scan,
        )
        residual_notice_required = bool(
            explicit_region_scope and residual_outside_scan,
        )
        return BillingRegionCoveragePayload(
            {
                "status": status,
                "selected_regions": selected,
                "explicit_region_scope": explicit_region_scope,
                "materiality_threshold": str(materiality_threshold),
                "billing_active_regions": active_regions,
                "billing_active_regions_outside_scan": outside_scan,
                "material_billing_active_regions": material_regions,
                "residual_billing_active_regions": residual_regions,
                "material_billing_active_regions_outside_scan": material_outside_scan,
                "residual_billing_active_regions_outside_scan": residual_outside_scan,
                "outside_scan_count": len(outside_scan),
                "material_outside_scan_count": len(material_outside_scan),
                "residual_outside_scan_count": len(residual_outside_scan),
                "billing_region_count": len(active_regions),
                "billing_global_or_unallocated_cost": str(global_or_unallocated_cost),
                "currency": currency,
                "current_period": {
                    "start_date": current_period.start_date.isoformat(),
                    "end_date": current_period.end_date.isoformat(),
                },
                "region_costs": region_records,
                "material_warning_required": material_warning_required,
                "residual_notice_required": residual_notice_required,
                "notice_required": (material_warning_required or residual_notice_required),
                "notice_severity": notice_severity,
                "limitations": limitations,
                "unrecognized_billing_region_values": unrecognized_region_values,
            },
        )


def normalize_billing_region(value: object) -> str | None:  # noqa: D103
    region = str(value or "").strip()
    normalized = region.lower().replace("_", " ")
    if normalized in GLOBAL_REGION_VALUES:
        return None
    if AWS_REGION_PATTERN.match(normalized):
        return normalized
    return "unknown"


def parse_decimal(value: object) -> Decimal:  # noqa: D103
    try:
        return Decimal(str(value or "0"))
    except Exception:  # noqa: BLE001
        return Decimal(0)
