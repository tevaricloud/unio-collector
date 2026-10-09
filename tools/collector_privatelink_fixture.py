"""Actual PrivateLink collection with populated synthetic endpoint observations."""

from __future__ import annotations

import json
from contextlib import nullcontext
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from tools.collector_ipv4_fixture import VARIANTS as BASE_VARIANTS
from tools.collector_ipv4_fixture import SyntheticIpv4Session
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.network.inventory import NetworkInventoryCollector
from unio_collector.aws.regional.inventory_helper import RegionalInventoryCollectionHelper
from unio_collector.scanners.network.privatelink.collector import NetworkPrivateLinkCostReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

SCANNER = "network-privatelink-cost-review"
VARIANTS = (*BASE_VARIANTS, "legacy_coverage", "regional_failure")


class SyntheticPrivateLinkSession(SyntheticIpv4Session):
    """Extend the finite offline EC2 fixture with the two endpoint operations."""

    def describe_vpc_endpoints(self, **kwargs: object) -> dict[str, Any]:
        """Emit public and customer service names, associations and optional metadata."""
        endpoint: dict[str, Any] = {
            "VpcEndpointId": "vpce-00000000000000000",
            "VpcId": "vpc-00000000000000000",
            "VpcEndpointType": "Interface",
            "ServiceName": "com.amazonaws.eu-west-2.ec2",
            "State": "Available",
            "RouteTableIds": ["rtb-00000000000000000"],
            "SubnetIds": ["subnet-00000000000000000"],
            "Tags": [{"Key": "Owner", "Value": "synthetic-customer"}],
        }
        if self.variant == "optional":
            endpoint["RouteTableIds"] = None
            endpoint["SubnetIds"] = []
            endpoint["VpcId"] = None
        if self.variant == "missing_id":
            endpoint.pop("VpcEndpointId")
        private = {
            "VpcEndpointId": "vpce-fffffffffffffffff",
            "VpcId": "vpc-00000000000000000",
            "VpcEndpointType": "GatewayLoadBalancer",
            "ServiceName": "com.amazonaws.vpce.eu-west-2.vpce-svc-00000000000000000",
            "State": "pendingAcceptance",
            "Tags": [],
        }
        return self._response("VpcEndpoints", [endpoint, private], kwargs)

    def describe_vpc_endpoint_service_configurations(self, **kwargs: object) -> dict[str, Any]:
        """Populate owned service identity and its fallback-name observation."""
        service = {
            "ServiceId": "vpce-svc-00000000000000000",
            "ServiceName": "com.amazonaws.vpce.eu-west-2.vpce-svc-00000000000000000",
            "Tags": [{"Key": "Name", "Value": "synthetic-customer-service"}],
        }
        if self.variant == "optional":
            service.pop("ServiceId")
        if self.variant == "missing_id":
            service = {"Tags": []}
        return self._response("ServiceConfigurations", [service], kwargs)


def privatelink_producer_case(variant: str = "success") -> dict[str, Any]:
    """Run the actual scanner, gateway, neutral collector, projection and serializer."""
    if variant not in VARIANTS:
        message = "Unknown synthetic PrivateLink variant."
        raise ValueError(message)
    session = SyntheticPrivateLinkSession(variant)
    definition: Any = SimpleNamespace(scanner_id=SCANNER)
    audit = AwsAuditContext(scanner_id=SCANNER, collector="NetworkInventoryCollector", allowed_api_calls=())
    collector = NetworkInventoryCollector(session, account_id="123456789012", audit_context=audit, selected_regions=["eu-west-2"])
    runtime: Any = SimpleNamespace(
        runtime_state=SimpleNamespace(account_id="123456789012"),
        get_cached_network_regions=lambda _d: ["eu-west-2"],
        create_network_collector=lambda *_a, **_k: collector,
        collect_cached_network_batch=lambda _d, collection_name, **_k: (
            collector.collected_batch(collection_name, {}) if variant == "legacy_coverage" else collector.collect_inventory_batch(collection_name)
        ),
    )

    with patch.object(RegionalInventoryCollectionHelper, "collect_region_records", return_value=[]) if variant == "regional_failure" else nullcontext():
        evidence = NetworkPrivateLinkCostReviewCollector(definition).collect(ScannerContext(runtime=runtime, definition=definition))
    return json.loads(json.dumps(build_scanner_evidence_payload(scanner_id=SCANNER, evidence=evidence)))


def add_privatelink_producer_payload(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Add actual populated endpoint output to the existing native smoke fixture."""
    row = privatelink_producer_case()
    if unknown:
        row["payload"]["topology"][0]["resources"][0]["facts"]["unknown_privatelink_container"] = {}
    add_scanner_producer_payload(files, row)
