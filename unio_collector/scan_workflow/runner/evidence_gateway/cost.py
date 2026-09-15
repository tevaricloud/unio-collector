from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.cost_explorer import CostExplorerResult, DailyCostRecord
    from unio_collector.scan_workflow.runner.evidence_gateway.protocols import (
        CostEvidenceSource,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class CostEvidenceGateway:
    """Delegate cost evidence collection to the cost evidence source."""

    def __init__(self, source: CostEvidenceSource) -> None:  # noqa: D107
        self._source = source

    def collect_cached_service_costs(
        self,
        definition: ScannerDefinition,
    ) -> CostExplorerResult:
        """Return cached service-level Cost Explorer evidence for a scanner."""
        return self._source.collect_cached_service_costs(definition)

    def collect_cached_daily_costs(
        self,
        definition: ScannerDefinition,
        *,
        group_keys: tuple[str, ...] = ("SERVICE",),
    ) -> list[DailyCostRecord]:
        """Return cached daily Cost Explorer evidence grouped by requested keys."""
        return self._source.collect_cached_daily_costs(
            definition,
            group_keys=group_keys,
        )

    def collect_cached_daily_costs_with_context(
        self,
        audit_context: AwsAuditContext,
        *,
        group_keys: tuple[str, ...] = ("SERVICE",),
    ) -> list[DailyCostRecord]:
        """Return cached daily costs for an explicit scanner audit context."""
        return self._source.collect_cached_daily_costs_with_context(
            audit_context,
            group_keys=group_keys,
        )
