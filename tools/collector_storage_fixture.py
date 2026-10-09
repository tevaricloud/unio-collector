"""Actual EC2 storage producers exercised with fixed synthetic SDK responses."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError

from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.aws.collection.diagnostics import AwsCollectionDiagnostics
from unio_collector.aws.ec2 import Ec2InventoryCollector
from unio_collector.scanners.inventory_evidence import InventoryEvidence
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

VARIANTS = ("success", "optional", "empty", "denied", "unsupported", "unavailable", "failure", "partial")
SCANNERS = ("ec2-unattached-ebs-volumes", "provisioned-iops-review", "ec2-stopped-instances-with-storage")


class SyntheticStorageSession:
    """Only return offline endpoint responses; never construct an SDK session."""

    def __init__(self, variant: str) -> None:
        """Select a known provider branch and deterministic serial collection."""
        self.variant = variant
        self.runtime_config = AwsRuntimeConfig(max_workers=1)
        self.collection_diagnostics = AwsCollectionDiagnostics()

    def create_client(self, service_name: str, *, region_name: str | None, audit_context: AwsAuditContext) -> SyntheticStorageSession:
        """Reject any unexpected service or region instead of making a live client."""
        del audit_context
        if service_name != "ec2" or region_name != "eu-west-2":
            message = "Unexpected synthetic storage endpoint."
            raise ValueError(message)
        return self

    def _fail(self, operation: str, kwargs: dict[str, object]) -> None:
        codes = {"denied": "UnauthorizedOperation", "unsupported": "UnsupportedOperation", "unavailable": "ServiceUnavailable", "failure": "InternalFailure"}
        code = codes.get(self.variant)
        if self.variant == "partial" and kwargs.get("NextToken"):
            code = "ThrottlingException"
        if code:
            raise ClientError({"Error": {"Code": code, "Message": "Synthetic unavailable operation"}}, operation)

    def describe_volumes(self, **kwargs: object) -> dict[str, Any]:
        """Exercise populated, nullable, empty and interrupted volume pagination."""
        self._fail("DescribeVolumes", kwargs)
        volume = {
            "VolumeId": "vol-00000000000000000",
            "Size": 100,
            "VolumeType": "io2",
            "State": "available",
            "CreateTime": datetime(2026, 9, 1, tzinfo=UTC),
            "Encrypted": True,
            "Iops": 3000,
            "Tags": [{"Key": "Name", "Value": "synthetic-customer-volume"}, {"Key": "Owner", "Value": "synthetic-customer-owner"}],
        }
        if self.variant == "optional":
            volume = {"VolumeId": "vol-00000000000000000"}
        return {"Volumes": [] if self.variant == "empty" else [volume], **({"NextToken": "synthetic-next"} if self.variant == "partial" else {})}

    def describe_instances(self, **kwargs: object) -> dict[str, Any]:
        """Exercise the current inventory-based stopped-instance producer path."""
        self._fail("DescribeInstances", kwargs)
        instance = {
            "InstanceId": "i-00000000000000000",
            "InstanceType": "m6i.large",
            "State": {"Name": "stopped"},
            "LaunchTime": datetime(2026, 9, 1, tzinfo=UTC),
            "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-00000000000000000"}}],
            "Tags": [{"Key": "Name", "Value": "synthetic-customer-instance"}, {"Key": "Owner", "Value": "synthetic-customer-owner"}],
        }
        if self.variant == "optional":
            instance = {"InstanceId": "i-00000000000000000", "State": {"Name": "stopped"}}
        return {
            "Reservations": [] if self.variant == "empty" else [{"Instances": [instance]}],
            **({"NextToken": "synthetic-next"} if self.variant == "partial" else {}),
        }


def storage_producer_case(scanner: str, variant: str = "success") -> tuple[dict[str, Any], list[str], list[str]]:
    """Serialize actual DTOs and retain actual task statuses and limitations."""
    if scanner not in SCANNERS or variant not in VARIANTS:
        message = "Unknown synthetic storage producer or variant."
        raise ValueError(message)
    session = SyntheticStorageSession(variant)
    collector = Ec2InventoryCollector(
        session,
        account_id="123456789012",
        audit_context=AwsAuditContext(scanner_id=scanner, collector="synthetic", allowed_api_calls=()),
        selected_regions=["eu-west-2"],
    )
    if scanner == SCANNERS[0]:
        records = collector.collect_unattached_volumes()
    elif scanner == SCANNERS[1]:
        records = collector.collect_provisioned_iops_volumes()
    else:
        records = collector.build_stopped_instance_records(instances_by_region=collector.collect_instances_by_region())
    payload = build_scanner_evidence_payload(scanner_id=scanner, evidence=InventoryEvidence(records=records, regions=collector.get_available_regions()))
    diagnostics = session.collection_diagnostics
    return payload, [result.status for result in diagnostics.get_results_since(0)], diagnostics.build_warning_messages_since(0)


def add_storage_producer_payloads(files: dict[str, bytes], *, unknown_field: bool = False) -> None:
    """Add populated and nullable actual records to the shared packaged smoke ZIP."""
    for scanner in SCANNERS:
        row, _, _ = storage_producer_case(scanner)
        optional, _, _ = storage_producer_case(scanner, "optional")
        row["payload"]["records"].extend(optional["payload"]["records"])
        if unknown_field:
            row["payload"]["records"][0]["unknown_storage_field"] = {}
        add_scanner_producer_payload(files, row)
