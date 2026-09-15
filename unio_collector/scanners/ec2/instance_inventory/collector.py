from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.ec2.instance_inventory.context import (
    Ec2InstanceInventoryContext,
)

if TYPE_CHECKING:
    from unio_collector.scanners.base import ScannerContext


def collect_ec2_instance_inventory_context(  # noqa: D103
    context: ScannerContext,
) -> Ec2InstanceInventoryContext:
    regions = context.ec2.get_regions()
    collector = context.ec2.create_collector(regions=regions)
    instances_by_region = context.ec2.collect_items_by_region(
        collection_name="instances",
        label="EC2 instance inventory",
        collect_items=lambda collector: collector.collect_instances_by_region(),
    )
    return Ec2InstanceInventoryContext(
        collector=collector,
        instances_by_region=instances_by_region,
        regions=collector.get_available_regions(),
    )
