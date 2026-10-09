"""Actual Elastic IP wrapper and inventory with synthetic SDK responses."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from tools.collector_scanner_fixture import add_scanner_producer_payload
from tools.collector_storage_fixture import SyntheticStorageSession
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.ec2 import Ec2InventoryCollector
from unio_collector.scanners.ec2.elastic_ip.collector import UnassociatedElasticIpCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

SCANNER = "ec2-unassociated-elastic-ips"
VARIANTS = ("success", "optional", "classic", "associated", "empty", "denied", "unsupported", "unavailable", "failure", "partial", "ip_only", "missing_ip")


class SyntheticAddressSession(SyntheticStorageSession):
    """Restrict provider responses to synthetic EC2 inventory endpoints."""

    def create_client(self, service_name: str, *, region_name: str | None, audit_context: AwsAuditContext) -> SyntheticAddressSession:
        """Use serial regions to exercise one failed region without real clients."""
        del audit_context
        if service_name != "ec2" or region_name not in {"eu-west-2", "eu-west-1"}:
            message = "Unexpected synthetic address endpoint."
            raise ValueError(message)
        self.region = region_name
        return self

    def describe_addresses(self, **kwargs: object) -> dict[str, Any]:
        """Populate all DTO fields and optional, filtered and failed branches."""
        self._fail("DescribeAddresses", {**kwargs, **({"NextToken": "synthetic"} if self.variant == "partial" and self.region == "eu-west-1" else {})})
        row: dict[str, Any] = {
            "AllocationId": "eipalloc-00000000000000000",
            "PublicIp": "192.0.2.10",
            "Domain": "vpc",
            "Tags": [{"Key": "Name", "Value": "synthetic-customer-address"}],
        }
        if self.variant == "optional":
            row = {}
        if self.variant == "classic":
            row["Domain"] = "standard"
        if self.variant == "associated":
            row["AssociationId"] = "eipassoc-00000000000000000"
        if self.variant == "ip_only":
            row.pop("AllocationId")
        if self.variant == "missing_ip":
            row.pop("PublicIp")
        return {"Addresses": [] if self.variant == "empty" else [row]}


def address_producer_case(variant: str = "success") -> tuple[dict[str, Any], list[str]]:
    """Cross actual wrapper, gateway, inventory and JSON serializer boundaries."""
    if variant not in VARIANTS:
        message = "Unknown synthetic address variant."
        raise ValueError(message)
    session = SyntheticAddressSession(variant)
    regions = ["eu-west-2", "eu-west-1"] if variant == "partial" else ["eu-west-2"]
    definition: Any = SimpleNamespace(scanner_id=SCANNER)
    collector = Ec2InventoryCollector(
        session,
        account_id="123456789012",
        selected_regions=regions,
        audit_context=AwsAuditContext(scanner_id=SCANNER, collector="Ec2InventoryCollector", allowed_api_calls=()),
    )
    runtime: Any = SimpleNamespace(
        collect_cached_ec2_records=lambda _d, *, collect_records, **_kwargs: collect_records(collector),
        get_cached_ec2_regions=lambda _d: regions,
    )
    evidence = UnassociatedElasticIpCollector(definition).collect(ScannerContext(runtime=runtime, definition=definition))
    row = json.loads(json.dumps(build_scanner_evidence_payload(scanner_id=SCANNER, evidence=evidence)))
    return row, [item.status for item in session.collection_diagnostics.get_results_since(0)]


def add_address_producer_payload(files: dict[str, bytes], *, unknown_field: bool = False) -> None:
    """Share populated, nullable and classic records with packaged smoke."""
    row, _ = address_producer_case()
    for variant in ("optional", "classic", "ip_only", "missing_ip"):
        extra, _ = address_producer_case(variant)
        row["payload"]["records"].extend(extra["payload"]["records"])
    if unknown_field:
        row["payload"]["unknown_address_container"] = {}
    add_scanner_producer_payload(files, row)
