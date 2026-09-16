from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.xray import (
    XRayInventoryCollector,
    extract_xray_cost_signal,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.scanner.implementation import ScannerImplementation
from unio_collector.scanners.xray.cost_evidence import (
    XRayCostGovernanceEvidence,
)

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class XRayTracingCostGovernanceReviewCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    def collect(self, context: ScannerContext) -> XRayCostGovernanceEvidence:  # noqa: D102
        collector = build_xray_collector(context)
        records = collector.collect_records()
        cost_data = context.costs.collect_service_costs()
        cost_signal = extract_xray_cost_signal(cost_data)
        return XRayCostGovernanceEvidence(
            records=records,
            cost_signal=cost_signal,
            regions=collector.get_available_regions(),
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="XRayTracingCostGovernanceReviewScanner",
            implementation_module="unio_collector.scanners.xray.tracing_scanner",
        )


def build_xray_collector(context: ScannerContext) -> XRayInventoryCollector:  # noqa: D103
    return context.security.create_regional_inventory_collector(
        XRayInventoryCollector,
        collector_name="XRayInventoryCollector",
    )
