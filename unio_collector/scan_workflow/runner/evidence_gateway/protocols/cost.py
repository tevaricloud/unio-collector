from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.cost_explorer import CostExplorerResult, DailyCostRecord
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class CostEvidenceSource(Protocol):
    """Cost evidence collection methods required by scanner runtime."""

    def collect_cached_service_costs(
        self,
        definition: ScannerDefinition,
    ) -> CostExplorerResult:
        """Return cached service-level Cost Explorer evidence for a scanner."""
        ...

    def collect_cached_daily_costs(
        self,
        definition: ScannerDefinition,
        *,
        group_keys: tuple[str, ...] = ("SERVICE",),
    ) -> list[DailyCostRecord]:
        """Return cached daily Cost Explorer evidence grouped by requested keys."""
        ...

    def collect_cached_daily_costs_with_context(
        self,
        audit_context: AwsAuditContext,
        *,
        group_keys: tuple[str, ...] = ("SERVICE",),
    ) -> list[DailyCostRecord]:
        """Return cached daily costs for an explicit scanner audit context."""
        ...
