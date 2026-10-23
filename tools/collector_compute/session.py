"""Synthetic SDK responses for actual instance and aggregate idle collectors."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from tools.collector_balancer_fixture import SyntheticBalancerSession
from tools.collector_storage_fixture import SyntheticStorageSession

if TYPE_CHECKING:
    from unio_collector.aws.audit.context import AwsAuditContext


class SyntheticComputeSession(SyntheticStorageSession):
    """Use finite offline responses while retaining real SDK orchestration and DTOs."""

    def __init__(self, variant: str, scanner: str) -> None:
        """Retain actual endpoint calls alongside collection diagnostics."""
        super().__init__(variant)
        self.scanner = scanner
        self.calls: list[str] = []
        self.metric_provider = SyntheticBalancerSession(variant)

    def create_client(self, service_name: str, *, region_name: str | None, audit_context: AwsAuditContext) -> SyntheticComputeSession:
        """Never construct an AWS session or accept unexpected endpoints."""
        del audit_context
        if service_name not in {"ec2", "cloudwatch"} or region_name != "eu-west-2":
            message = "Unexpected synthetic compute endpoint."
            raise ValueError(message)
        return self

    def describe_instances(self, **kwargs: object) -> dict[str, Any]:
        """Populate running and stopped records, limits, nullable and interrupted pages."""
        self.calls.append("DescribeInstances")
        self._fail("DescribeInstances", kwargs)
        running: dict[str, Any] = {
            "InstanceId": "i-00000000000000001",
            "InstanceType": "m6i.large",
            "State": {"Name": "running"},
            "LaunchTime": datetime(2026, 5, 1, tzinfo=UTC),
            "RootDeviceType": "ebs",
            "InstanceLifecycle": "spot",
            "PlatformDetails": "Linux/UNIX",
            "Placement": {"Tenancy": "default"},
            "VpcId": "vpc-00000000000000000",
            "SubnetId": "subnet-00000000000000000",
            "PublicIpAddress": "198.51.100.24",
            "Tags": [
                {"Key": "Name", "Value": "synthetic-customer-instance"},
                {"Key": "aws:autoscaling:groupName", "Value": "synthetic-customer-group"},
                {"Key": "eks:cluster-name", "Value": "synthetic-customer-cluster"},
            ],
        }
        stopped = {
            **running,
            "InstanceId": "i-00000000000000002",
            "State": {"Name": "stopped"},
            "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-00000000000000000"}}],
        }
        if self.variant == "optional":
            running = {"InstanceId": "i-00000000000000001", "State": {"Name": "running"}}
            stopped = {"InstanceId": "i-00000000000000002", "State": {"Name": "stopped"}}
        if self.variant == "nullable":
            running.update(LaunchTime=None, VpcId=None, SubnetId=None, PublicIpAddress=None, RootDeviceType=None, Placement=None)
        if self.variant == "collision":
            running["Tags"] = [{"Key": "Name", "Value": "running"}, {"Key": "Owner", "Value": "AWS/EC2"}]
            stopped["Tags"] = [{"Key": "Name", "Value": "m6i.large"}, {"Key": "Owner", "Value": "stopped"}]
        if self.variant == "schedule_collision":
            running["Tags"] = [{"Key": "Name", "Value": "mon"}, {"Key": "Owner", "Value": "Europe/London"}]
        if self.variant == "identity_collision":
            tags = [
                {"Key": "Name", "Value": self.scanner},
                {"Key": "Owner", "Value": "InventoryEvidence"},
                {"Key": "Team", "Value": "Ec2InventoryEvidenceBundle"},
            ]
            running["Tags"] = tags
            stopped["Tags"] = tags
        instances = [running, {**running, "InstanceId": "i-00000000000000003"}, stopped]
        return {
            "Reservations": [] if self.variant == "empty" else [{"Instances": instances}],
            **({"NextToken": "synthetic-next"} if self.variant == "partial" else {}),
        }

    def describe_addresses(self) -> dict[str, Any]:
        """Collect real elastic-IP DTOs, including absent optional metadata."""
        self.calls.append("DescribeAddresses")
        self._fail("DescribeAddresses", {})
        row = {
            "AllocationId": "eipalloc-00000000000000000",
            "PublicIp": "198.51.100.25",
            "Domain": "vpc",
            "Tags": [{"Key": "Name", "Value": "synthetic-customer-address"}],
        }
        return {"Addresses": [] if self.variant == "empty" else [{} if self.variant == "optional" else row]}

    def get_metric_data(self, **kwargs: Any) -> dict[str, Any]:  # noqa: ANN401
        """Retain real metric parsing, aggregation, partial results and fallback."""
        self.calls.append("GetMetricData")
        return self.metric_provider.get_metric_data(**kwargs)

    def get_metric_statistics(self, **kwargs: object) -> dict[str, Any]:
        """Use the actual fallback path for unavailable metric reads."""
        self.calls.append("GetMetricStatistics")
        return self.metric_provider.get_metric_statistics(**kwargs)

    def describe_volumes(self, **kwargs: object) -> dict[str, Any]:
        """Drive the actual aggregate EBS producer with finite-control text as customer tags."""
        response = super().describe_volumes(**kwargs)
        if self.variant == "collision":
            for volume in response["Volumes"]:
                volume["Tags"] = [{"Key": "Name", "Value": "available"}, {"Key": "Owner", "Value": "gp3"}]
        return response
