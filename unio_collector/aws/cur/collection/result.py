from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class CurBillingResult:
    """Exact in-memory billing aggregates; serialize only the bounded projection."""

    source_files: tuple[str, ...]
    rows_read: int
    rows_matched: int
    rows_skipped: int
    currency: str
    total_cost: Decimal
    service_costs: dict[str, Decimal]
    region_costs: dict[str, Decimal]
    usage_type_costs: dict[str, Decimal]
    resource_costs: dict[str, Decimal]
    tag_costs: dict[tuple[str, str], Decimal]
    unassigned_cost: Decimal
    top_resources: list[dict[str, Any]]
    limitations: list[str]

    reason_codes: tuple[str, ...] = ()
