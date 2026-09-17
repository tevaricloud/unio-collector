from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.ec2.ebs.provisioned_iops import ProvisionedIopsScanner
    from unio_collector.scanners.ec2.ebs.unattached_volume import UnattachedEbsVolumeScanner
    from unio_collector.scanners.ec2.elastic_ip.unassociated import UnassociatedElasticIpScanner
    from unio_collector.scanners.ec2.idle_instance.scanner import Ec2IdleInstanceReviewScanner
    from unio_collector.scanners.ec2.instance_inventory.collector import collect_ec2_instance_inventory_context
    from unio_collector.scanners.ec2.instance_inventory.context import Ec2InstanceInventoryContext
    from unio_collector.scanners.ec2.instance_storage.stopped import StoppedInstanceStorageScanner
    from unio_collector.scanners.ec2.inventory.cached_scanner import CachedEc2InventoryScanner
    from unio_collector.scanners.ec2.inventory.evidence_bundle import Ec2InventoryEvidenceBundle
    from unio_collector.scanners.ec2.packs import EC2_SCANNER_PACKS, EC2_SCANNER_TYPES
    from unio_collector.scanners.idle.zombie_resource import IdleZombieResourceScanner
    from unio_collector.scanners.network.nat_gateway.inventory_scanner import NatGatewayInventoryScanner

_EXPORTS = {
    "EC2_SCANNER_PACKS": ("unio_collector.scanners.ec2.packs", "EC2_SCANNER_PACKS"),
    "EC2_SCANNER_TYPES": ("unio_collector.scanners.ec2.packs", "EC2_SCANNER_TYPES"),
    "CachedEc2InventoryScanner": ("unio_collector.scanners.ec2.inventory.cached_scanner", "CachedEc2InventoryScanner"),
    "Ec2IdleInstanceReviewScanner": ("unio_collector.scanners.ec2.idle_instance.scanner", "Ec2IdleInstanceReviewScanner"),
    "Ec2InstanceInventoryContext": ("unio_collector.scanners.ec2.instance_inventory.context", "Ec2InstanceInventoryContext"),
    "Ec2InventoryEvidenceBundle": ("unio_collector.scanners.ec2.inventory.evidence_bundle", "Ec2InventoryEvidenceBundle"),
    "IdleZombieResourceScanner": ("unio_collector.scanners.idle.zombie_resource", "IdleZombieResourceScanner"),
    "NatGatewayInventoryScanner": ("unio_collector.scanners.network.nat_gateway.inventory_scanner", "NatGatewayInventoryScanner"),
    "ProvisionedIopsScanner": ("unio_collector.scanners.ec2.ebs.provisioned_iops", "ProvisionedIopsScanner"),
    "StoppedInstanceStorageScanner": ("unio_collector.scanners.ec2.instance_storage.stopped", "StoppedInstanceStorageScanner"),
    "UnassociatedElasticIpScanner": ("unio_collector.scanners.ec2.elastic_ip.unassociated", "UnassociatedElasticIpScanner"),
    "UnattachedEbsVolumeScanner": ("unio_collector.scanners.ec2.ebs.unattached_volume", "UnattachedEbsVolumeScanner"),
    "collect_ec2_instance_inventory_context": ("unio_collector.scanners.ec2.instance_inventory.collector", "collect_ec2_instance_inventory_context"),
}

__all__ = [
    "EC2_SCANNER_PACKS",
    "EC2_SCANNER_TYPES",
    "CachedEc2InventoryScanner",
    "Ec2IdleInstanceReviewScanner",
    "Ec2InstanceInventoryContext",
    "Ec2InventoryEvidenceBundle",
    "IdleZombieResourceScanner",
    "NatGatewayInventoryScanner",
    "ProvisionedIopsScanner",
    "StoppedInstanceStorageScanner",
    "UnassociatedElasticIpScanner",
    "UnattachedEbsVolumeScanner",
    "collect_ec2_instance_inventory_context",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve retained public exports without importing private analysis eagerly."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
