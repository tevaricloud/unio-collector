from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from unio_collector.aws.cur.collection.result import CurBillingResult
from unio_collector.aws.cur.line.factory import CurLineItemFactory
from unio_collector.aws.cur.summary import (
    build_cur_limitations,
    build_top_resource_records,
    get_tag_value,
)

if TYPE_CHECKING:
    from unio_collector.aws.cur.line.item import CurLineItem
    from unio_collector.aws.cur.path.result import CurPathResolutionResult
    from unio_collector.core.scan.period import ScanPeriod


@dataclass
class CurBillingAccumulator:
    """Accumulate matched CUR/Data Export line items for one scan period."""

    group_by_tags: tuple[str, ...]
    rows_read: int = 0
    rows_matched: int = 0
    rows_skipped: int = 0
    currency: str = "USD"
    unassigned_cost: Decimal = Decimal(0)
    service_costs: dict[str, Decimal] = field(default_factory=dict)
    region_costs: dict[str, Decimal] = field(default_factory=dict)
    usage_type_costs: dict[str, Decimal] = field(default_factory=dict)
    resource_costs: dict[str, Decimal] = field(default_factory=dict)
    resource_context: dict[str, dict[str, Any]] = field(default_factory=dict)
    tag_costs: dict[tuple[str, str], Decimal] = field(default_factory=dict)

    def record_row(  # noqa: D102
        self,
        row: dict[str, str],
        scan_period: ScanPeriod,
    ) -> None:
        self.rows_read += 1
        item = CurLineItemFactory(row).create_line_item()
        if item is None:
            self.rows_skipped += 1
            return
        if not is_within_scan_period(item, scan_period):
            return
        self.record_line_item(item)

    def record_line_item(self, item: CurLineItem) -> None:  # noqa: D102
        if not item.cost.is_finite():
            msg = "CUR/Data Export cost must be finite."
            raise ValueError(msg)
        if self.rows_matched and item.currency and item.currency != self.currency:
            msg = "CUR/Data Export matched rows contain mixed currencies."
            raise ValueError(msg)
        self.rows_matched += 1
        self.currency = item.currency or self.currency
        add_decimal(self.service_costs, item.service_name or "Unknown", item.cost)
        add_decimal(self.region_costs, item.region or "global", item.cost)
        add_decimal(self.usage_type_costs, item.usage_type or "Unknown", item.cost)
        self.record_resource_cost(item)
        if not self.record_tag_costs(item):
            self.unassigned_cost += item.cost

    def record_resource_cost(self, item: CurLineItem) -> None:  # noqa: D102
        if not item.resource_id:
            return
        add_decimal(self.resource_costs, item.resource_id, item.cost)
        self.resource_context.setdefault(
            item.resource_id,
            {
                "resource_id": item.resource_id,
                "service": item.service_name,
                "region": item.region or "global",
                "account_id": item.account_id,
                "usage_type": item.usage_type,
            },
        )

    def record_tag_costs(self, item: CurLineItem) -> bool:  # noqa: D102
        matched_tag = False
        for tag_key in self.group_by_tags:
            tag_value = get_tag_value(item.tags, tag_key)
            if not tag_value:
                continue
            matched_tag = True
            add_decimal(self.tag_costs, (tag_key, tag_value), item.cost)
        return matched_tag

    def build_observations(  # noqa: D102
        self,
        path_resolution: CurPathResolutionResult,
    ) -> CurBillingResult:
        return CurBillingResult(
            source_files=tuple(source.name for source in path_resolution.data_sources),
            rows_read=self.rows_read,
            rows_matched=self.rows_matched,
            rows_skipped=self.rows_skipped,
            currency=self.currency,
            total_cost=sum(self.service_costs.values(), Decimal(0)),
            service_costs=self.service_costs,
            region_costs=self.region_costs,
            usage_type_costs=self.usage_type_costs,
            resource_costs=self.resource_costs,
            tag_costs=self.tag_costs,
            unassigned_cost=self.unassigned_cost,
            top_resources=build_top_resource_records(
                self.resource_costs,
                self.resource_context,
            ),
            limitations=build_cur_limitations(path_resolution.limitations),
            reason_codes=path_resolution.reason_codes,
        )


def is_within_scan_period(item: CurLineItem, scan_period: ScanPeriod) -> bool:  # noqa: D103
    return scan_period.current_start_date <= item.usage_start_date <= scan_period.current_end_date


def add_decimal(mapping: dict[Any, Decimal], key: Any, amount: Decimal) -> None:  # noqa: ANN401, D103
    mapping[key] = mapping.get(key, Decimal(0)) + amount
