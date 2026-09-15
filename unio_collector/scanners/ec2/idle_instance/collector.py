from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.scanners.ec2.instance_inventory.collector import (
    collect_ec2_instance_inventory_context,
)
from unio_collector.scanners.ec2.inventory.collector import CachedEc2InventoryCollector
from unio_collector.scanners.inventory_evidence import InventoryEvidence
from unio_collector.scanners.options import parse_scanner_option_int
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class Ec2IdleInstanceReviewCollector(CachedEc2InventoryCollector):
    """Collect provider evidence for ec2-idle-instance-review."""

    collection_name = "running_instances"

    def collect(self, context: ScannerContext) -> InventoryEvidence:  # noqa: D102
        max_instances_per_region = self.get_max_instances_per_region(context)
        self.record_instance_limit_note(context, max_instances_per_region)
        inventory = collect_ec2_instance_inventory_context(context)
        return InventoryEvidence(
            records=inventory.collector.build_running_instance_records(
                instances_by_region=inventory.instances_by_region,
                scan_period=context.options.get_scan_period(),
                max_instances_per_region=max_instances_per_region,
            ),
            regions=inventory.regions,
            metadata={
                "scheduled_shutdown": context.options.get(
                    "scheduled_shutdown",
                    None,
                ),
            },
        )

    def get_period_key(self, context: ScannerContext) -> str | None:  # noqa: D102
        max_instances_per_region = self.get_max_instances_per_region(context)
        limit_key = max_instances_per_region or "all"
        return context.options.get_scan_period().current_start_date.isoformat() + f":max-instances-per-region:{limit_key}"

    def collect_records(self, collector: Any) -> list[Any]:  # noqa: ANN401, D102
        return collector.collect_running_instances()

    def get_max_instances_per_region(  # noqa: D102
        self,
        context: ScannerContext,
    ) -> int | None:
        value = parse_scanner_option_int(
            context.options.get(
                "max_instances_per_region",
                0,
            ),
        )
        if value <= 0:
            return None
        return value

    def record_instance_limit_note(  # noqa: D102
        self,
        context: ScannerContext,
        max_instances_per_region: int | None,
    ) -> None:
        if max_instances_per_region is None:
            return
        context.warnings.add_coverage_note(
            {
                "note_type": "configuration_limit",
                "scope_area": "ec2_running_instance_metrics",
                "summary": (f"EC2 idle instance metric collection was capped at {max_instances_per_region} running instance(s) per region for this scan."),
                "configured_limit": max_instances_per_region,
                "config_key": "ec2-idle-instance-review.max_instances_per_region",
                "result_scope": "current_scan",
                "impact": (
                    "Running instance inventory and utilization review are bounded for faster development scans. Use 0 for full per-region metric coverage."
                ),
            },
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="Ec2IdleInstanceReviewScanner",
            implementation_module="unio_collector.scanners.ec2.idle_instance.scanner",
        )
