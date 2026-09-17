from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.network.metrics import NetworkMetricCollector
from unio_collector.aws.network.projection import build_network_topology
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.network.nat_gateway.evidence import NatGatewayCostEvidence
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class NatGatewayCostReviewCollector(BaseUnioScanner):
    """Collect network evidence without running finding interpretation."""

    def collect(self, context: ScannerContext) -> NatGatewayCostEvidence:  # noqa: D102
        regions = context.network.get_regions()
        batch = context.network.collect_batch(
            collection_name="nat_gateways", label="NAT Gateway inventory", collect_items=lambda collector: collector.collect_nat_gateways_by_region()
        )
        collector = context.network.create_collector(
            regions=regions,
        )
        observed_regions = sorted({item.region for item in batch.coverage})
        nat_gateways = collector.build_nat_gateway_records(nat_gateways_by_region=batch.as_dictionary(), regions=observed_regions)
        metrics = NetworkMetricCollector(collector.session, audit_context=collector.audit_context, regions=sorted({gateway.region for gateway in nat_gateways}))
        return NatGatewayCostEvidence(
            nat_gateways=metrics.add_nat_gateway_metrics(
                nat_gateways,
                context.options.get_scan_period(),
            ),
            daily_costs=context.costs.collect_daily_costs(
                group_keys=("SERVICE", "USAGE_TYPE"),
            ),
            regions=sorted(set(regions) | {"global"}),
            network_evidence_version="neutral-topology-v1",
            topology=build_network_topology(account_id=collector.account_id, regions=observed_regions, batches=(batch,)),
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="NatGatewayCostReviewScanner",
            implementation_module="unio_collector.scanners.network.nat_gateway.scanner",
        )
