from __future__ import annotations  # noqa: D104

from typing import TYPE_CHECKING, Any, TypeVar

from unio_collector.aws.ebs.provisioned_iops import ProvisionedIopsVolumeRecord
from unio_collector.aws.ebs.volume_record import EbsVolumeRecord
from unio_collector.aws.ec2.elastic_ip_record import ElasticIpRecord
from unio_collector.aws.ec2.helpers import build_ec2_arn, first_attachment, tags_to_dict
from unio_collector.aws.ec2.instances import Ec2InstanceMixin
from unio_collector.aws.ec2.region_instances import Ec2RegionInstanceInventory
from unio_collector.aws.ec2.running_instance_record import RunningInstanceRecord
from unio_collector.aws.ec2.stopped_instance_record import StoppedInstanceRecord
from unio_collector.aws.ec2.volumes import Ec2VolumeMixin
from unio_collector.aws.inventory_helpers import (
    AwsEc2RegionDiscoveryHelper,
    AwsInventoryTagHelper,
    AwsInventoryValueHelper,
    RegionalInventoryCollectionHelper,
)
from unio_collector.aws.metric.context import MetricCollectionContext
from unio_collector.aws.metric.request import MetricRequest
from unio_collector.aws.network.nat_gateway_record import NatGatewayRecord
from unio_collector.aws.pagination import AwsPaginationHelper
from unio_collector.aws.taggable_resource_record import TaggableResourceRecord

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.cloudwatch.metric_collector import CloudWatchMetricCollector
    from unio_collector.aws.metric.summary import MetricSummary
    from unio_collector.core.scan.period import ScanPeriod

InventoryRecordT = TypeVar("InventoryRecordT")


class Ec2InventoryCollector(Ec2InstanceMixin, Ec2VolumeMixin):
    """Read-only EC2 inventory collector."""

    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        selected_regions: list[str] | None = None,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.selected_regions = selected_regions
        self._available_regions_cache: list[str] | None = None
        self._pagination = AwsPaginationHelper()
        self._regions = AwsEc2RegionDiscoveryHelper(
            self.session,
            audit_context=self.audit_context,
        )
        self._tags = AwsInventoryTagHelper()
        self._values = AwsInventoryValueHelper()
        self._regional_collection = RegionalInventoryCollectionHelper(
            self.session,
            account_id=self.account_id,
            audit_context=self.audit_context,
            collector_id="Ec2InventoryCollector",
        )

    def collect_unattached_volumes(self) -> list[EbsVolumeRecord]:  # noqa: D102
        return self._collect_region_records(
            operation="DescribeVolumes",
            collect_region=self._collect_unattached_volumes_in_region,
        )

    def collect_unused_elastic_ips(self) -> list[ElasticIpRecord]:  # noqa: D102
        return self._collect_region_records(
            operation="DescribeAddresses",
            collect_region=self._collect_unused_elastic_ips_in_region,
        )

    def collect_stopped_instances(self) -> list[StoppedInstanceRecord]:  # noqa: D102
        return self._collect_region_records(
            operation="DescribeInstances",
            collect_region=self._collect_stopped_instances_in_region,
        )

    def collect_instances_by_region(self) -> dict[str, list[dict[str, Any]]]:  # noqa: D102
        records = self._regional_collection.collect_region_records(
            regions=self.get_available_regions(),
            service="ec2",
            operation="DescribeInstances",
            collect_region=self._collect_instance_inventory_in_region,
        )
        return {record.region: list(record.instances) for record in records}

    def build_stopped_instance_records(  # noqa: D102
        self,
        *,
        instances_by_region: dict[str, list[dict[str, Any]]],
    ) -> list[StoppedInstanceRecord]:
        records: list[StoppedInstanceRecord] = []
        for region in self.get_available_regions():
            records.extend(
                self._build_stopped_instance_records(
                    region=region,
                    instances=instances_by_region.get(region, []),
                ),
            )
        return records

    def build_running_instance_records(  # noqa: D102
        self,
        *,
        instances_by_region: dict[str, list[dict[str, Any]]],
        scan_period: ScanPeriod | None = None,
        max_instances_per_region: int | None = None,
    ) -> list[RunningInstanceRecord]:
        records: list[RunningInstanceRecord] = []
        for region in self.get_available_regions():
            records.extend(
                self._build_running_instance_records(
                    region=region,
                    instances=instances_by_region.get(region, []),
                    scan_period=scan_period,
                    max_instances_per_region=max_instances_per_region,
                ),
            )
        return records

    def collect_nat_gateways(self) -> list[NatGatewayRecord]:  # noqa: D102
        return self._collect_region_records(
            operation="DescribeNatGateways",
            collect_region=self._collect_nat_gateways_in_region,
        )

    def collect_taggable_resources(  # noqa: D102
        self,
        *,
        include_nat_gateways: bool = True,
    ) -> list[TaggableResourceRecord]:
        return self._collect_region_records(
            operation="DescribeInstances",
            collect_region=(
                lambda region: self._collect_taggable_resources_in_region(
                    region,
                    include_nat_gateways=include_nat_gateways,
                )
            ),
        )

    def collect_running_instances(  # noqa: D102
        self,
        scan_period: ScanPeriod | None = None,
        *,
        max_instances_per_region: int | None = None,
    ) -> list[RunningInstanceRecord]:
        return self._collect_region_records(
            operation="DescribeInstances",
            collect_region=lambda region: self._collect_running_instances_in_region(
                region,
                scan_period,
                max_instances_per_region,
            ),
        )

    def _collect_running_instance_metrics(
        self,
        metric_collector: CloudWatchMetricCollector,
        scan_period: ScanPeriod | None,
        instance_id: str,
    ) -> list[MetricSummary]:
        if scan_period is None:
            return []
        dimensions = [{"Name": "InstanceId", "Value": instance_id}]
        requests = self._build_running_instance_metric_requests(
            scan_period,
            dimensions,
        )
        return metric_collector.collect_metric_summaries(requests)

    def _build_running_instance_metric_requests(
        self,
        scan_period: ScanPeriod,
        dimensions: list[dict[str, str]],
    ) -> list[MetricRequest]:
        return [
            MetricRequest(
                namespace="AWS/EC2",
                metric_name="CPUUtilization",
                dimensions=dimensions,
                statistic="Average",
                period=3600,
                start_time=scan_period.current_start_datetime,
                end_time=scan_period.current_end_exclusive_datetime,
                collection_context=MetricCollectionContext.EC2_INSTANCE,
            ),
            MetricRequest(
                namespace="AWS/EC2",
                metric_name="NetworkIn",
                dimensions=dimensions,
                statistic="Average",
                period=3600,
                start_time=scan_period.current_start_datetime,
                end_time=scan_period.current_end_exclusive_datetime,
                collection_context=MetricCollectionContext.EC2_INSTANCE,
            ),
            MetricRequest(
                namespace="AWS/EC2",
                metric_name="NetworkOut",
                dimensions=dimensions,
                statistic="Average",
                period=3600,
                start_time=scan_period.current_start_datetime,
                end_time=scan_period.current_end_exclusive_datetime,
                collection_context=MetricCollectionContext.EC2_INSTANCE,
            ),
            MetricRequest(
                namespace="AWS/EC2",
                metric_name="DiskReadOps",
                dimensions=dimensions,
                statistic="Average",
                period=3600,
                start_time=scan_period.current_start_datetime,
                end_time=scan_period.current_end_exclusive_datetime,
                collection_context=MetricCollectionContext.EC2_INSTANCE,
            ),
            MetricRequest(
                namespace="AWS/EC2",
                metric_name="DiskWriteOps",
                dimensions=dimensions,
                statistic="Average",
                period=3600,
                start_time=scan_period.current_start_datetime,
                end_time=scan_period.current_end_exclusive_datetime,
                collection_context=MetricCollectionContext.EC2_INSTANCE,
            ),
            MetricRequest(
                namespace="AWS/EC2",
                metric_name="StatusCheckFailed",
                dimensions=dimensions,
                statistic="Maximum",
                period=3600,
                start_time=scan_period.current_start_datetime,
                end_time=scan_period.current_end_exclusive_datetime,
                collection_context=MetricCollectionContext.EC2_INSTANCE,
            ),
        ]

    def collect_provisioned_iops_volumes(self) -> list[ProvisionedIopsVolumeRecord]:  # noqa: D102
        return self._collect_region_records(
            operation="DescribeVolumes",
            collect_region=self._collect_provisioned_iops_volumes_in_region,
        )

    def _collect_region_records(
        self,
        *,
        operation: str,
        collect_region: Callable[[str], list[InventoryRecordT]],
    ) -> list[InventoryRecordT]:
        return self._regional_collection.collect_region_records(
            regions=self.get_available_regions(),
            service="ec2",
            operation=operation,
            collect_region=collect_region,
        )

    def _collect_unattached_volumes_in_region(
        self,
        region: str,
    ) -> list[EbsVolumeRecord]:
        client = self.session.create_client(
            "ec2",
            region_name=region,
            audit_context=self.audit_context,
        )
        records: list[EbsVolumeRecord] = [
            EbsVolumeRecord(
                volume_id=volume["VolumeId"],
                account_id=self.account_id,
                region=region,
                size_gib=volume.get("Size", 0),
                volume_type=volume.get("VolumeType", "unknown"),
                state=volume.get("State", "unknown"),
                create_time=volume.get("CreateTime"),
                encrypted=volume.get("Encrypted"),
                tags=self._tags.tags_to_dict(volume.get("Tags", [])),
            )
            for volume in self._collect_volume_items(
                client,
                request_parameters={
                    "Filters": [{"Name": "status", "Values": ["available"]}],
                    "MaxResults": 500,
                },
            )
        ]
        return records

    def _collect_unused_elastic_ips_in_region(
        self,
        region: str,
    ) -> list[ElasticIpRecord]:
        records: list[ElasticIpRecord] = []
        client = self.session.create_client(
            "ec2",
            region_name=region,
            audit_context=self.audit_context,
        )
        response = client.describe_addresses()
        for address in response.get("Addresses", []):
            if address.get("AssociationId"):
                continue
            records.append(
                ElasticIpRecord(
                    allocation_id=address.get("AllocationId"),
                    public_ip=address.get("PublicIp"),
                    account_id=self.account_id,
                    region=region,
                    domain=address.get("Domain"),
                    tags=self._tags.tags_to_dict(address.get("Tags", [])),
                ),
            )
        return records

    def _collect_stopped_instances_in_region(
        self,
        region: str,
    ) -> list[StoppedInstanceRecord]:
        client = self.session.create_client(
            "ec2",
            region_name=region,
            audit_context=self.audit_context,
        )
        return self._build_stopped_instance_records(
            region=region,
            instances=self._collect_instances(
                client,
                filters=[{"Name": "instance-state-name", "Values": ["stopped"]}],
            ),
        )

    def _collect_instance_inventory_in_region(
        self,
        region: str,
    ) -> list[Ec2RegionInstanceInventory]:
        client = self.session.create_client(
            "ec2",
            region_name=region,
            audit_context=self.audit_context,
        )
        return [
            Ec2RegionInstanceInventory(
                region=region,
                instances=self._collect_instances(client),
            ),
        ]

    def _collect_instances(
        self,
        client: Any,  # noqa: ANN401
        *,
        filters: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        request_parameters: dict[str, Any] = {"MaxResults": 1000}
        if filters:
            request_parameters["Filters"] = filters
        pages = self._pagination.collect_token_pages(
            client,
            "describe_instances",
            result_key="Reservations",
            request_parameters=request_parameters,
        ).pages
        return [
            instance
            for page in pages
            for reservation in page.get("Reservations", [])
            if isinstance(reservation, dict)
            for instance in reservation.get("Instances", [])
            if isinstance(instance, dict)
        ]

    def _build_stopped_instance_records(
        self,
        *,
        region: str,
        instances: list[dict[str, Any]],
    ) -> list[StoppedInstanceRecord]:
        records: list[StoppedInstanceRecord] = []
        for instance in instances:
            if self._get_instance_state_name(instance) != "stopped":
                continue
            volume_ids = [
                mapping.get("Ebs", {}).get("VolumeId") for mapping in instance.get("BlockDeviceMappings", []) if mapping.get("Ebs", {}).get("VolumeId")
            ]
            records.append(
                StoppedInstanceRecord(
                    instance_id=instance["InstanceId"],
                    account_id=self.account_id,
                    region=region,
                    instance_type=instance.get("InstanceType", "unknown"),
                    launch_time=instance.get("LaunchTime"),
                    attached_volume_ids=volume_ids,
                    tags=self._tags.tags_to_dict(instance.get("Tags", [])),
                ),
            )
        return records


__all__ = [
    "EbsVolumeRecord",
    "Ec2InventoryCollector",
    "Ec2RegionInstanceInventory",
    "ElasticIpRecord",
    "NatGatewayRecord",
    "ProvisionedIopsVolumeRecord",
    "RunningInstanceRecord",
    "StoppedInstanceRecord",
    "TaggableResourceRecord",
    "build_ec2_arn",
    "first_attachment",
    "tags_to_dict",
]
