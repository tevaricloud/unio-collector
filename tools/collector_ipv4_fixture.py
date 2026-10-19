"""Actual regional public IPv4 wrapper and neutral inventory with synthetic SDK data."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from botocore.exceptions import ClientError

from tools.collector_balancer_fixture import SyntheticBalancerSession
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.network.inventory import NetworkInventoryCollector
from unio_collector.scanners.network.public_ipv4.collector import NetworkPublicIpv4ReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

SCANNER = "network-public-ipv4-review"
VARIANTS = (
    "success",
    "optional",
    "empty",
    "denied",
    "unsupported",
    "unavailable",
    "failure",
    "partial",
    "malformed",
    "cycle",
    "repeat",
    "conflict",
    "missing_id",
)


class SyntheticIpv4Session(SyntheticBalancerSession):
    """Serve only declared offline EC2 operations and reject unexpected access."""

    def create_client(self, service_name: str, *, region_name: str | None, audit_context: AwsAuditContext) -> SyntheticIpv4Session:
        """Return this synthetic client without creating an SDK session."""
        del audit_context
        if service_name != "ec2" or region_name != "eu-west-2":
            message = "Unexpected synthetic public IPv4 endpoint."
            raise ValueError(message)
        return self

    def _response(self, key: str, items: list[dict[str, Any]], parameters: dict[str, object]) -> dict[str, Any]:
        code = {
            "denied": "UnauthorizedOperation",
            "unsupported": "UnsupportedOperation",
            "unavailable": "ServiceUnavailable",
            "failure": "InternalFailure",
        }.get(self.variant)
        if self.variant == "partial" and parameters.get("NextToken"):
            code = "ThrottlingException"
        if code:
            raise ClientError({"Error": {"Code": code, "Message": "Synthetic customer diagnostic"}}, "Describe" + key)
        if self.variant == "malformed":
            return {key: "invalid-array"}
        if self.variant == "empty":
            items = []
        if self.variant in {"repeat", "conflict"}:
            items = [*items, dict(items[0])]
            if self.variant == "conflict":
                items[-1]["TagSet" if key == "NetworkInterfaces" else "Tags"] = [{"Key": "Owner", "Value": "synthetic-conflict"}]
        return {key: items, **({"NextToken": "synthetic-next"} if self.variant in {"partial", "cycle"} else {})}

    def describe_addresses(self, **kwargs: object) -> dict[str, Any]:
        """Emit attached and fallback-IP identities with typed tags."""
        address = {
            "AllocationId": "eipalloc-00000000000000000",
            "AssociationId": "eipassoc-00000000000000000",
            "PublicIp": "203.0.113.10",
            "Tags": [{"Key": "Owner", "Value": "synthetic-customer"}],
        }
        if self.variant == "optional":
            address["AssociationId"] = None
        if self.variant == "missing_id":
            address = {"Tags": []}
        return self._response("Addresses", [address, {"PublicIp": "203.0.113.11"}], kwargs)

    def describe_network_interfaces(self, **kwargs: object) -> dict[str, Any]:
        """Populate every projected interface member including nested optional fields."""
        interface = {
            "NetworkInterfaceId": "eni-00000000000000000",
            "VpcId": "vpc-00000000000000000",
            "SubnetId": "subnet-00000000000000000",
            "InterfaceType": "interface",
            "Description": "synthetic-customer network",
            "RequesterManaged": False,
            "Attachment": {"InstanceId": "i-00000000000000000"},
            "Association": {"PublicIp": "203.0.113.10", "AllocationId": "eipalloc-00000000000000000"},
            "TagSet": [{"Key": "Owner", "Value": "synthetic-customer"}],
        }
        if self.variant == "optional":
            interface["Description"] = None
            interface["RequesterManaged"] = None
            interface["Attachment"] = None
        if self.variant == "missing_id":
            interface.pop("NetworkInterfaceId")
        return self._response(
            "NetworkInterfaces", [interface, {"NetworkInterfaceId": "eni-fffffffffffffffff", "Association": {"PublicIp": "203.0.113.11"}}], kwargs
        )


def ipv4_producer_case(variant: str = "success") -> dict[str, Any]:
    """Invoke the actual wrapper, network gateway, collection, projection and serializer."""
    if variant not in VARIANTS:
        message = "Unknown synthetic public IPv4 variant."
        raise ValueError(message)
    session = SyntheticIpv4Session(variant)
    definition: Any = SimpleNamespace(scanner_id=SCANNER)
    audit = AwsAuditContext(scanner_id=SCANNER, collector="NetworkInventoryCollector", allowed_api_calls=())
    collector = NetworkInventoryCollector(session, account_id="123456789012", audit_context=audit, selected_regions=["eu-west-2"])
    runtime: Any = SimpleNamespace(
        runtime_state=SimpleNamespace(account_id="123456789012"),
        get_cached_network_regions=lambda _d: ["eu-west-2"],
        create_network_collector=lambda *_args, **_kwargs: collector,
        collect_cached_network_batch=lambda _d, collection_name, **_kwargs: collector.collect_inventory_batch(collection_name),
    )
    evidence = NetworkPublicIpv4ReviewCollector(definition).collect(ScannerContext(runtime=runtime, definition=definition))
    return json.loads(json.dumps(build_scanner_evidence_payload(scanner_id=SCANNER, evidence=evidence)))


def add_ipv4_producer_payload(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Add populated current public IPv4 branches to the existing native fixture."""
    row = ipv4_producer_case()
    if unknown:
        row["payload"]["topology"][0]["resources"][0]["facts"]["unknown_network_container"] = {}
    add_scanner_producer_payload(files, row)
