from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws.ec2.helpers import tags_to_dict
from unio_collector.aws.network.batch import NetworkInventoryBatch
from unio_collector.aws.network.coverage import NetworkCollectionCoverage
from unio_collector.aws.network.nat_gateway_record import NatGatewayRecord
from unio_collector.aws.network.operations import NETWORK_OPERATIONS, NetworkOperationCollector
from unio_collector.aws.network.projection import NetworkTopologyProjection
from unio_collector.aws.regional.inventory_helper import RegionalInventoryCollectionHelper

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.ec2.public_ipv4_record import PublicIpv4RegionRecord
    from unio_collector.aws.network.private_link_record import PrivateLinkRegionRecord
    from unio_collector.aws.network.transit_gateway_record import TransitGatewayRegionRecord


class NetworkInventoryCollector(NetworkTopologyProjection):
    """Collect neutral, read-only AWS network inventory."""

    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        selected_regions: list[str] | None = None,
    ) -> None:
        self.session = session
        super().__init__(account_id)
        self.audit_context = audit_context
        self.selected_regions = selected_regions
        self._batches: dict[str, NetworkInventoryBatch] = {}
        self._operations = NetworkOperationCollector(session, account_id=account_id, audit_context=audit_context)
        self._regional_collection = RegionalInventoryCollectionHelper(
            self.session,
            account_id=self.account_id,
            audit_context=self.audit_context,
            collector_id="NetworkInventoryCollector",
        )
        self._available_regions_cache: list[str] | None = None

    def collect_public_ipv4_region_records(self) -> list[PublicIpv4RegionRecord]:  # noqa: D102
        return self.build_public_ipv4_region_records(
            addresses_by_region=self.collect_addresses_by_region(),
            network_interfaces_by_region=(self.collect_network_interfaces_by_region()),
        )

    def collect_addresses_by_region(self) -> dict[str, list[dict[str, Any]]]:  # noqa: D102
        return self.collect_inventory_batch("addresses").as_dictionary()

    def collect_vpcs_by_region(self) -> dict[str, list[dict[str, Any]]]:  # noqa: D102
        return self.collect_inventory_batch("vpcs").as_dictionary()

    def collect_network_interfaces_by_region(self) -> dict[str, list[dict[str, Any]]]:  # noqa: D102
        return self.collect_inventory_batch("network_interfaces").as_dictionary()

    def collect_route_tables_by_region(self) -> dict[str, list[dict[str, Any]]]:  # noqa: D102
        return self.collect_inventory_batch("route_tables").as_dictionary()

    def collect_vpc_endpoints_by_region(self) -> dict[str, list[dict[str, Any]]]:  # noqa: D102
        return self.collect_inventory_batch("vpc_endpoints").as_dictionary()

    def collect_vpc_endpoint_service_configurations_by_region(  # noqa: D102
        self,
    ) -> dict[str, list[dict[str, Any]]]:
        return self.collect_inventory_batch("vpc_endpoint_service_configurations").as_dictionary()

    def collect_nat_gateways_by_region(self) -> dict[str, list[dict[str, Any]]]:  # noqa: D102
        return self.collect_inventory_batch("nat_gateways").as_dictionary()

    def collect_subnets_by_region(self) -> dict[str, list[dict[str, Any]]]:  # noqa: D102
        return self.collect_inventory_batch("subnets").as_dictionary()

    def build_public_ipv4_region_records(  # noqa: D102
        self,
        *,
        addresses_by_region: dict[str, list[dict[str, Any]]],
        network_interfaces_by_region: dict[str, list[dict[str, Any]]],
    ) -> list[PublicIpv4RegionRecord]:
        return [
            self.build_public_ipv4_region_record(
                region=region,
                addresses=addresses_by_region.get(region, []),
                interfaces=network_interfaces_by_region.get(region, []),
            )
            for region in self.get_available_regions()
        ]

    def build_nat_gateway_records(  # noqa: D102
        self,
        *,
        nat_gateways_by_region: dict[str, list[dict[str, Any]]],
        regions: list[str] | None = None,
    ) -> list[NatGatewayRecord]:
        records: list[NatGatewayRecord] = []
        for region in self.get_available_regions() if regions is None else regions:
            for gateway in nat_gateways_by_region.get(region, []):
                gateway_id = gateway.get("NatGatewayId")
                if not gateway_id:
                    continue
                records.append(
                    NatGatewayRecord(
                        nat_gateway_id=str(gateway_id),
                        account_id=self.account_id,
                        region=region,
                        state=str(gateway.get("State") or "unknown"),
                        subnet_id=(str(gateway.get("SubnetId")) if gateway.get("SubnetId") else None),
                        vpc_id=(str(gateway.get("VpcId")) if gateway.get("VpcId") else None),
                        connectivity_type=(str(gateway.get("ConnectivityType")) if gateway.get("ConnectivityType") else None),
                        create_time=gateway.get("CreateTime"),
                        tags=tags_to_dict(gateway.get("Tags", [])),
                    ),
                )
        return records

    def build_privatelink_region_records(  # noqa: D102
        self,
        *,
        endpoints_by_region: dict[str, list[dict[str, Any]]],
        service_configurations_by_region: dict[str, list[dict[str, Any]]],
    ) -> list[PrivateLinkRegionRecord]:
        records: list[PrivateLinkRegionRecord] = []
        for region in self.get_available_regions():
            records.extend(
                self.build_privatelink_region_record(
                    region=region,
                    endpoints=endpoints_by_region.get(region, []),
                    service_configurations=(service_configurations_by_region.get(region, [])),
                ),
            )
        return records

    def get_available_regions(self) -> list[str]:  # noqa: D102
        if self._available_regions_cache is not None:
            return self._available_regions_cache
        if self.selected_regions:
            self._available_regions_cache = sorted(self.selected_regions)
            return self._available_regions_cache
        client = self.session.create_client(
            "ec2",
            region_name=self.session.get_region_name() or "us-east-1",
            audit_context=self.audit_context,
        )
        response = client.describe_regions(AllRegions=False)
        self._available_regions_cache = sorted(region["RegionName"] for region in response.get("Regions", []))
        return self._available_regions_cache

    def collect_inventory_batch(self, collection_name: str) -> NetworkInventoryBatch:
        """Collect a regional batch while retaining failure metadata in the cache value."""
        regions = self.get_available_regions()
        records = self._regional_collection.collect_region_records(
            regions=regions,
            service="ec2",
            operation="".join(part.title() for part in NETWORK_OPERATIONS[collection_name][0].split("_")),
            collect_region=lambda region: [self._operations.collect(collection_name, region)],
        )
        by_region = {region: items for batch in records for region, items in batch.items_by_region.items()}
        coverage = tuple(item for batch in records for item in batch.coverage)
        observed = {item.region for item in coverage}
        coverage += tuple(
            NetworkCollectionCoverage(self.account_id, collection_name, region, collection_name, "unavailable", reason_codes=("api_failure",))
            for region in regions
            if region not in observed
        )
        batch = NetworkInventoryBatch(self.account_id, collection_name, by_region, coverage)
        self._batches[collection_name] = batch
        return batch

    def collected_batch(self, collection_name: str, items: dict[str, list[dict[str, Any]]]) -> NetworkInventoryBatch:
        """Return authoritative outcomes after a compatibility collection callback."""
        if collection_name in self._batches:
            return self._batches[collection_name]
        return NetworkInventoryBatch(
            self.account_id,
            collection_name,
            items,
            tuple(
                NetworkCollectionCoverage(self.account_id, collection_name, region, collection_name, "skipped", reason_codes=("legacy_coverage_unknown",))
                for region in self.get_available_regions()
            ),
        )

    def collect_transit_gateway_region_records(self) -> list[TransitGatewayRegionRecord]:
        """Retain the historical neutral TGW counts and response-order samples."""
        gateways, attachments, tables = self._collect_group(("transit_gateways", "transit_gateway_attachments", "transit_gateway_route_tables"))
        return [
            record
            for region in self.get_available_regions()
            for record in self.build_transit_gateway_region_record(
                region=region,
                gateways=gateways.items_by_region.get(region, []),
                attachments=attachments.items_by_region.get(region, []),
                route_tables=tables.items_by_region.get(region, []),
            )
        ]

    def collected_batches(self) -> tuple[NetworkInventoryBatch, ...]:
        """Return captured inventory and outcomes without provider access."""
        return tuple(self._batches.values())

    def collect_privatelink_region_records(self) -> list[PrivateLinkRegionRecord]:
        """Retain the historical neutral PrivateLink summary interface."""
        endpoints, services = self._collect_group(("vpc_endpoints", "vpc_endpoint_service_configurations"))
        return self.build_privatelink_region_records(endpoints_by_region=endpoints.as_dictionary(), service_configurations_by_region=services.as_dictionary())

    def _collect_group(self, names: tuple[str, ...]) -> tuple[NetworkInventoryBatch, ...]:
        def collect_region(region: str) -> list[NetworkInventoryBatch]:
            client = self.session.create_client("ec2", region_name=region, audit_context=self.audit_context)
            return [self._operations.collect(name, region, client=client) for name in names]

        regions = self.get_available_regions()
        records = self._regional_collection.collect_region_records(
            regions=regions,
            service="ec2",
            operation="+".join("".join(part.title() for part in NETWORK_OPERATIONS[name][0].split("_")) for name in names),
            collect_region=collect_region,
        )
        batches = []
        for name in names:
            selected = [record for record in records if record.collection_name == name]
            coverage = tuple(entry for record in selected for entry in record.coverage)
            seen = {entry.region for entry in coverage}
            coverage += tuple(
                NetworkCollectionCoverage(self.account_id, name, region, name, "unavailable", reason_codes=("api_failure",))
                for region in regions
                if region not in seen
            )
            batch = NetworkInventoryBatch(
                self.account_id, name, {region: items for record in selected for region, items in record.items_by_region.items()}, coverage
            )
            self._batches[name] = batch
            batches.append(batch)
        return tuple(batches)
