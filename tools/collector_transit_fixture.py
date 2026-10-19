"""Actual transit collection with synthetic attachment types, states and ownership."""

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
from unio_collector.aws.regional.inventory_helper import RegionalInventoryCollectionHelper
from unio_collector.scanners.network.transit_gateway.collector import NetworkTransitGatewayCostReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

SCANNER = "network-transit-gateway-cost-review"
VARIANTS = (*BASE_VARIANTS, "types", "states", "regional_failure", "mixed_case")
TYPES = ("vpc", "vpn", "vpn-concentrator", "direct-connect-gateway", "connect", "peering", "tgw-peering", "network-function", "client-vpn", None)
STATES = (
    "initiating",
    "initiatingRequest",
    "pendingAcceptance",
    "rollingBack",
    "pending",
    "available",
    "modifying",
    "deleting",
    "deleted",
    "failed",
    "rejected",
    "rejecting",
    "failing",
)


class SyntheticTransitSession(SyntheticIpv4Session):
    """Serve only offline transit inventory through the actual bulk collection path."""

    def describe_transit_gateways(self, **kwargs: object) -> dict[str, Any]:
        """Include stable IDs and existing tag-key policy inputs."""
        gateway = {"TransitGatewayId": "tgw-00000000000000000", "Tags": [{"Key": "Name", "Value": "synthetic-customer-gateway"}]}
        if self.variant == "missing_id":
            gateway.pop("TransitGatewayId")
        return self._response("TransitGateways", [gateway], kwargs)

    def describe_transit_gateway_attachments(self, **kwargs: object) -> dict[str, Any]:
        """Exercise every finite provider type/state plus absent optional ownership."""
        kinds = TYPES if self.variant == "types" else ("vpc", "vpn")
        states = STATES if self.variant == "states" else ("available",) * len(kinds)
        rows: list[dict[str, Any]] = []
        for index, state in enumerate(states):
            sentinel = format(index, "017b").replace("1", "f")
            row = {
                "TransitGatewayAttachmentId": "tgw-attach-" + sentinel,
                "TransitGatewayId": "tgw-00000000000000000",
                "ResourceId": "vpc-" + sentinel,
                "ResourceType": kinds[index % len(kinds)],
                "ResourceOwnerId": "123456789012" if index == 0 else "210987654321",
                "State": state,
                "Tags": [{"Key": "Owner", "Value": "synthetic-customer"}],
            }
            if self.variant == "types":
                row["Tags"].append({"Key": "Department", "Value": "network"})
            if self.variant == "optional":
                row.update(ResourceId=None, ResourceType=None, ResourceOwnerId=None, Tags=[])
            if self.variant == "missing_id":
                row.pop("TransitGatewayAttachmentId")
            if self.variant == "mixed_case":
                row.update(ResourceType=str(row["ResourceType"]).upper(), State=str(row["State"]).upper())
            rows.append(row)
        return self._response("TransitGatewayAttachments", rows, kwargs)

    def describe_transit_gateway_route_tables(self, **kwargs: object) -> dict[str, Any]:
        """Retain gateway references in the existing route-table projection."""
        return self._response(
            "TransitGatewayRouteTables",
            [{"TransitGatewayRouteTableId": "tgw-rtb-00000000000000000", "TransitGatewayId": "tgw-00000000000000000", "Tags": []}],
            kwargs,
        )


def transit_producer_case(variant: str = "success") -> dict[str, Any]:
    """Invoke actual scanner/security gateway, bulk inventory and serialized topology."""
    if variant not in VARIANTS:
        message = "Unknown synthetic transit variant."
        raise ValueError(message)
    session = SyntheticTransitSession(variant)
    definition: Any = SimpleNamespace(scanner_id=SCANNER)
    audit = AwsAuditContext(scanner_id=SCANNER, collector="NetworkInventoryCollector", allowed_api_calls=())
    runtime: Any = SimpleNamespace(
        runtime_state=SimpleNamespace(account_id="123456789012", session=session, get_selected_regions=lambda: ["eu-west-2"]),
        create_audit_context=lambda *_a: audit,
    )
    with patch.object(RegionalInventoryCollectionHelper, "collect_region_records", return_value=[]) if variant == "regional_failure" else nullcontext():
        evidence = NetworkTransitGatewayCostReviewCollector(definition).collect(ScannerContext(runtime=runtime, definition=definition))
    return json.loads(json.dumps(build_scanner_evidence_payload(scanner_id=SCANNER, evidence=evidence)))


def add_transit_producer_payload(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Share actual populated transit type counts and ownership with native smoke."""
    row = transit_producer_case("types")
    if unknown:
        row["payload"]["records"][0]["attachment_resource_type_counts"]["unknown_transit_type"] = 1
    add_scanner_producer_payload(files, row)
