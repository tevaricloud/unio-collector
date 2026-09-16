from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.ec2.instance_inventory.collector import (
    collect_ec2_instance_inventory_context,
)
from unio_collector.scanners.ec2.inventory.evidence_bundle import Ec2InventoryEvidenceBundle
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class IdleZombieResourceCollector(BaseUnioScanner):
    """Collect provider evidence for idle-zombie-resource-detector."""

    def collect(self, context: ScannerContext) -> Ec2InventoryEvidenceBundle:  # noqa: D102
        instance_inventory = collect_ec2_instance_inventory_context(context)
        return Ec2InventoryEvidenceBundle(
            elastic_ips=context.ec2.collect_records(
                collection_name="unused_elastic_ips",
                collect_records=lambda collector: collector.collect_unused_elastic_ips(),
            ),
            ebs_volumes=context.ec2.collect_records(
                collection_name="unattached_volumes",
                collect_records=lambda collector: collector.collect_unattached_volumes(),
            ),
            stopped_instances=(
                instance_inventory.collector.build_stopped_instance_records(
                    instances_by_region=instance_inventory.instances_by_region,
                )
            ),
            nat_gateways=context.network.collect_nat_gateway_records(),
            regions=instance_inventory.regions,
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="IdleZombieResourceScanner",
            implementation_module="unio_collector.scanners.idle.zombie_resource",
        )
