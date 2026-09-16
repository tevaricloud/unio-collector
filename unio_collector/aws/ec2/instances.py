# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any

from unio_collector.aws.cloudwatch.metric_collector import CloudWatchMetricCollector
from unio_collector.aws.ebs.provisioned_iops import ProvisionedIopsVolumeRecord
from unio_collector.aws.ec2.helpers import build_ec2_arn, first_attachment
from unio_collector.aws.ec2.running_instance_record import RunningInstanceRecord
from unio_collector.aws.inventory_helpers import (
    AwsInventoryTagHelper,
)
from unio_collector.aws.network.nat_gateway_record import NatGatewayRecord
from unio_collector.aws.response_admission import require_complete_response, require_response_rows, require_response_string
from unio_collector.aws.taggable_resource_record import TaggableResourceRecord

if TYPE_CHECKING:
    from unio_collector.aws.metric.request import MetricRequest
    from unio_collector.aws.metric.summary import MetricSummary
    from unio_collector.core.scan.period import ScanPeriod

_TAG_HELPER = AwsInventoryTagHelper()


class Ec2InstanceMixin:  # noqa: D101
    def _collect_nat_gateways_in_region(
        self,
        region: str,
    ) -> list[NatGatewayRecord]:
        client = self.session.create_client(
            "ec2",
            region_name=region,
            audit_context=self.audit_context,
        )
        records: list[NatGatewayRecord] = [
            NatGatewayRecord(
                nat_gateway_id=gateway["NatGatewayId"],
                account_id=self.account_id,
                region=region,
                state=gateway.get("State", "unknown"),
                subnet_id=gateway.get("SubnetId"),
                vpc_id=gateway.get("VpcId"),
                connectivity_type=gateway.get("ConnectivityType"),
                create_time=gateway.get("CreateTime"),
                tags=self._tags.tags_to_dict(gateway.get("Tags", [])),
            )
            for gateway in self._collect_nat_gateway_items(client)
        ]
        return records

    def _collect_taggable_resources_in_region(
        self,
        region: str,
        *,
        include_nat_gateways: bool = True,
    ) -> list[TaggableResourceRecord]:
        records: list[TaggableResourceRecord] = []
        client = self.session.create_client(
            "ec2",
            region_name=region,
            audit_context=self.audit_context,
        )
        vpc_context = self._collect_taggable_vpcs(client, region, records)
        subnet_context = self._collect_taggable_subnets(
            client,
            region,
            records,
            vpc_context,
        )
        instance_context = self._collect_taggable_instances(
            client,
            region,
            records,
            subnet_context,
            vpc_context,
        )
        self._collect_taggable_volumes(client, region, records, instance_context)
        self._collect_taggable_elastic_ips(client, region, records)
        if include_nat_gateways:
            self._collect_taggable_nat_gateways(
                client,
                region,
                records,
                subnet_context,
                vpc_context,
            )
        return records

    def _collect_running_instances_in_region(
        self,
        region: str,
        scan_period: ScanPeriod | None,
        max_instances_per_region: int | None,
    ) -> list[RunningInstanceRecord]:
        client = self.session.create_client(
            "ec2",
            region_name=region,
            audit_context=self.audit_context,
        )
        return self._build_running_instance_records(
            region=region,
            instances=self._collect_instances(
                client,
                filters=[{"Name": "instance-state-name", "Values": ["running"]}],
            ),
            scan_period=scan_period,
            max_instances_per_region=max_instances_per_region,
        )

    def _build_running_instance_records(
        self,
        *,
        region: str,
        instances: list[dict[str, Any]],
        scan_period: ScanPeriod | None,
        max_instances_per_region: int | None,
    ) -> list[RunningInstanceRecord]:
        records: list[RunningInstanceRecord] = []
        metric_collector = CloudWatchMetricCollector(
            self.session,
            region=region,
            audit_context=self.audit_context,
        )
        for instance in instances:
            if self._get_instance_state_name(instance) != "running":
                continue
            tags = self._tags.tags_to_dict(instance.get("Tags", []))
            records.append(
                RunningInstanceRecord(
                    instance_id=instance["InstanceId"],
                    account_id=self.account_id,
                    region=region,
                    instance_type=instance.get("InstanceType", "unknown"),
                    launch_time=instance.get("LaunchTime"),
                    tags=tags,
                    metric_summaries=[],
                    root_device_type=str(
                        instance.get("RootDeviceType") or "unknown",
                    ),
                    instance_lifecycle=str(
                        instance.get("InstanceLifecycle") or "on-demand",
                    ),
                    platform_details=str(instance.get("PlatformDetails") or instance.get("Platform") or "unknown"),
                    tenancy=str(
                        (instance.get("Placement") or {}).get("Tenancy") or "default",
                    ),
                    vpc_id=instance.get("VpcId"),
                    subnet_id=instance.get("SubnetId"),
                    public_ip_address=instance.get("PublicIpAddress"),
                    managed_workload_markers=self._managed_workload_markers(tags),
                ),
            )
            if max_instances_per_region is not None and len(records) >= max_instances_per_region:
                return self._add_running_instance_metrics(
                    records,
                    metric_collector,
                    scan_period,
                )
        return self._add_running_instance_metrics(
            records,
            metric_collector,
            scan_period,
        )

    def _managed_workload_markers(
        self,
        tags: dict[str, str],
    ) -> tuple[str, ...]:
        markers: list[str] = []
        normalized_keys = {key.casefold() for key in tags}
        checks = {
            "autoscaling": ("aws:autoscaling:groupname",),
            "ecs": ("aws:ecs:clustername", "ecs:cluster"),
            "eks": ("kubernetes.io/cluster/", "eks:cluster-name"),
            "emr": ("aws:elasticmapreduce:job-flow-id",),
        }
        for label, prefixes in checks.items():
            if any(any(key == prefix or key.startswith(prefix) for prefix in prefixes) for key in normalized_keys):
                markers.append(label)
        return tuple(markers)

    def _get_instance_state_name(self, instance: dict[str, Any]) -> str:
        state = instance.get("State", {})
        if isinstance(state, dict):
            return str(state.get("Name") or "").lower()
        return str(state or "").lower()

    def _add_running_instance_metrics(
        self,
        records: list[RunningInstanceRecord],
        metric_collector: CloudWatchMetricCollector,
        scan_period: ScanPeriod | None,
    ) -> list[RunningInstanceRecord]:
        if scan_period is None or not records:
            return records
        requests: list[MetricRequest] = []
        record_indexes: list[int] = []
        for index, record in enumerate(records):
            dimensions = [{"Name": "InstanceId", "Value": record.instance_id}]
            metric_requests = self._build_running_instance_metric_requests(
                scan_period,
                dimensions,
            )
            requests.extend(metric_requests)
            record_indexes.extend([index] * len(metric_requests))
        summaries_by_record: dict[int, list[MetricSummary]] = {index: [] for index in range(len(records))}
        for index, summary in zip(
            record_indexes,
            metric_collector.collect_metric_summaries(requests),
            strict=True,
        ):
            summaries_by_record[index].append(summary)
        return [replace(record, metric_summaries=summaries_by_record[index]) for index, record in enumerate(records)]

    def _collect_provisioned_iops_volumes_in_region(
        self,
        region: str,
    ) -> list[ProvisionedIopsVolumeRecord]:
        client = self.session.create_client(
            "ec2",
            region_name=region,
            audit_context=self.audit_context,
        )
        records: list[ProvisionedIopsVolumeRecord] = [
            ProvisionedIopsVolumeRecord(
                volume_id=volume["VolumeId"],
                account_id=self.account_id,
                region=region,
                volume_type=volume.get("VolumeType", "unknown"),
                size_gib=volume.get("Size", 0),
                provisioned_iops=volume.get("Iops"),
                state=volume.get("State", "unknown"),
                tags=self._tags.tags_to_dict(volume.get("Tags", [])),
            )
            for volume in self._collect_volume_items(
                client,
                request_parameters={
                    "Filters": [{"Name": "volume-type", "Values": ["io1", "io2"]}],
                    "MaxResults": 500,
                },
            )
        ]
        return records

    def get_available_regions(self) -> list[str]:  # noqa: D102
        if self._available_regions_cache is not None:
            return self._available_regions_cache
        self._available_regions_cache = self._regions.get_available_regions(
            self.selected_regions,
        )
        return self._available_regions_cache

    def _collect_taggable_instances(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        records: list[TaggableResourceRecord],
        subnet_context: dict[str, TaggableResourceRecord],
        vpc_context: dict[str, TaggableResourceRecord],
    ) -> dict[str, TaggableResourceRecord]:
        instance_context: dict[str, TaggableResourceRecord] = {}
        for instance in self._collect_instances(client):
            instance_id = instance["InstanceId"]
            tags = self._tags.tags_to_dict(instance.get("Tags", []))
            associated_record = subnet_context.get(
                str(instance.get("SubnetId") or ""),
            ) or vpc_context.get(str(instance.get("VpcId") or ""))
            record = TaggableResourceRecord(
                resource_id=instance_id,
                resource_type="EC2 instance",
                service="Amazon EC2",
                account_id=self.account_id,
                region=region,
                resource_name=tags.get("Name"),
                arn=build_ec2_arn(
                    region,
                    self.account_id,
                    "instance",
                    instance_id,
                ),
                tags=tags,
                associated_resource_id=(associated_record.resource_id if associated_record else None),
                associated_resource_type=(associated_record.resource_type if associated_record else None),
                associated_resource_tags=(associated_record.tags if associated_record else {}),
                association_reason=("EC2 instance is launched in this tagged network resource." if associated_record else None),
            )
            records.append(record)
            instance_context[instance_id] = record
        return instance_context

    def _collect_taggable_vpcs(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        records: list[TaggableResourceRecord],
    ) -> dict[str, TaggableResourceRecord]:
        vpc_context: dict[str, TaggableResourceRecord] = {}
        response = client.describe_vpcs()
        require_complete_response(response)
        for vpc in require_response_rows(response, "Vpcs"):
            vpc_id = require_response_string(vpc.get("VpcId"))
            tags = self._tags.tags_to_dict(vpc.get("Tags", []))
            record = TaggableResourceRecord(
                resource_id=vpc_id,
                resource_type="VPC",
                service="Amazon VPC",
                account_id=self.account_id,
                region=region,
                resource_name=tags.get("Name"),
                arn=build_ec2_arn(region, self.account_id, "vpc", vpc_id),
                tags=tags,
            )
            records.append(record)
            vpc_context[vpc_id] = record
        return vpc_context

    def _collect_taggable_subnets(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        records: list[TaggableResourceRecord],
        vpc_context: dict[str, TaggableResourceRecord],
    ) -> dict[str, TaggableResourceRecord]:
        subnet_context: dict[str, TaggableResourceRecord] = {}
        response = client.describe_subnets()
        require_complete_response(response)
        for subnet in require_response_rows(response, "Subnets"):
            subnet_id = require_response_string(subnet.get("SubnetId"))
            tags = self._tags.tags_to_dict(subnet.get("Tags", []))
            vpc_record = vpc_context.get(str(subnet.get("VpcId") or ""))
            record = TaggableResourceRecord(
                resource_id=subnet_id,
                resource_type="Subnet",
                service="Amazon VPC",
                account_id=self.account_id,
                region=region,
                resource_name=tags.get("Name"),
                arn=build_ec2_arn(region, self.account_id, "subnet", subnet_id),
                tags=tags,
                associated_resource_id=vpc_record.resource_id if vpc_record else None,
                associated_resource_type=vpc_record.resource_type if vpc_record else None,
                associated_resource_tags=vpc_record.tags if vpc_record else {},
                association_reason=("Subnet belongs to this tagged VPC." if vpc_record else None),
            )
            records.append(record)
            subnet_context[subnet_id] = record
        return subnet_context

    def _collect_taggable_volumes(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        records: list[TaggableResourceRecord],
        instance_context: dict[str, TaggableResourceRecord],
    ) -> None:
        for volume in self._collect_volume_items(
            client,
            request_parameters={"MaxResults": 500},
        ):
            volume_id = volume["VolumeId"]
            tags = self._tags.tags_to_dict(volume.get("Tags", []))
            attachment = first_attachment(volume.get("Attachments", []))
            instance_id = attachment.get("InstanceId") if attachment else None
            associated_record = instance_context.get(instance_id or "")
            records.append(
                TaggableResourceRecord(
                    resource_id=volume_id,
                    resource_type="EBS volume",
                    service="Amazon Elastic Block Store",
                    account_id=self.account_id,
                    region=region,
                    resource_name=tags.get("Name"),
                    arn=build_ec2_arn(
                        region,
                        self.account_id,
                        "volume",
                        volume_id,
                    ),
                    tags=tags,
                    associated_resource_id=(associated_record.resource_id if associated_record else None),
                    associated_resource_type=(associated_record.resource_type if associated_record else None),
                    associated_resource_tags=(associated_record.tags if associated_record else {}),
                    association_reason=("EBS volume is directly attached to this EC2 instance." if associated_record else None),
                ),
            )

    def _collect_taggable_elastic_ips(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        records: list[TaggableResourceRecord],
    ) -> None:
        response = client.describe_addresses()
        require_complete_response(response)
        for address in require_response_rows(response, "Addresses"):
            tags = self._tags.tags_to_dict(address.get("Tags", []))
            resource_id = require_response_string(address.get("AllocationId") or address.get("PublicIp"))
            records.append(
                TaggableResourceRecord(
                    resource_id=resource_id,
                    resource_type="Elastic IP",
                    service="Amazon EC2",
                    account_id=self.account_id,
                    region=region,
                    resource_name=address.get("PublicIp"),
                    tags=tags,
                ),
            )
