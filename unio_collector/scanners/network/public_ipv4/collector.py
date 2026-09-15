from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.network.projection import build_network_topology
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.network.public_ipv4.evidence import PublicIpv4Evidence
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class NetworkPublicIpv4ReviewCollector(BaseUnioScanner):
    """Collect network evidence without running finding interpretation."""

    def collect(self, context: ScannerContext) -> PublicIpv4Evidence:  # noqa: D102
        regions = context.network.get_regions()
        collector = context.network.create_collector(regions=regions)
        addresses_by_region = context.network.collect_batch(
            collection_name="addresses",
            label="EC2 public IPv4 address inventory",
            collect_items=lambda collector: collector.collect_addresses_by_region(),
        )
        interfaces_by_region = context.network.collect_batch(
            collection_name="network_interfaces",
            label="EC2 network interface inventory",
            collect_items=(lambda collector: collector.collect_network_interfaces_by_region()),
        )
        records = collector.build_public_ipv4_region_records(
            addresses_by_region=addresses_by_region.as_dictionary(),
            network_interfaces_by_region=interfaces_by_region.as_dictionary(),
        )
        return PublicIpv4Evidence(
            records=records,
            regions=collector.get_available_regions(),
            network_evidence_version="neutral-topology-v1",
            topology=build_network_topology(
                account_id=collector.account_id,
                regions=regions,
                batches=(
                    addresses_by_region,
                    interfaces_by_region,
                ),
            ),
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="NetworkPublicIpv4ReviewScanner",
            implementation_module="unio_collector.scanners.network.public_ipv4.scanner",
        )
