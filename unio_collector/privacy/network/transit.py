"""Closed transit-gateway observations with finite attachment type counts."""

from typing import ClassVar

from unio_collector.privacy.network.base import NetworkPrivacyContract
from unio_collector.privacy.network.fields import FIELDS as TOPOLOGY_FIELDS

RESOURCE_TYPES = frozenset(
    {"vpc", "vpn", "vpn-concentrator", "direct-connect-gateway", "connect", "peering", "tgw-peering", "network-function", "client-vpn", "unknown"}
)
COUNTS = (
    "transit_gateway_count",
    "attachment_count",
    "active_attachment_count",
    "active_vpc_attachment_count",
    "active_vpn_attachment_count",
    "active_peering_attachment_count",
    "active_direct_connect_attachment_count",
    "active_connect_attachment_count",
    "cross_account_attachment_count",
    "route_table_count",
    "tagged_transit_gateway_count",
    "tagged_attachment_count",
    "untagged_transit_gateway_count",
    "untagged_active_attachment_count",
)
SAMPLES = ("sample_transit_gateway_ids", "sample_attachment_ids", "sample_cross_account_attachment_ids", "sample_route_table_ids")
FIELDS = {
    **TOPOLOGY_FIELDS,
    "records": ("array", "safe_metadata", False),
    "records[]": ("object", "safe_metadata", False),
    "records[].account_id": ("string", "aws_account_id", False),
    "records[].region": ("string", "region", False),
    **{f"records[].{key}": ("count", "safe_metadata", False) for key in COUNTS},
    **{f"records[].{key}": ("array", "safe_metadata", False) for key in SAMPLES},
    **{f"records[].{key}[]": ("string", "resource_id", False) for key in SAMPLES},
    "records[].attachment_resource_type_counts": ("object", "safe_metadata", False),
    **{f"records[].attachment_resource_type_counts.{key}": ("count", "safe_metadata", False) for key in RESOURCE_TYPES},
    "records[].sample_attachment_resource_types": ("array", "safe_metadata", False),
    "records[].sample_attachment_resource_types[]": ("attachment_type", "safe_metadata", False),
}


class TransitGatewayPrivacyContract(NetworkPrivacyContract):
    """Preserve count semantics and cross-account relationships without raw identifiers."""

    collection_names: ClassVar[frozenset[str]] = frozenset({"transit_gateways", "transit_gateway_attachments", "transit_gateway_route_tables"})
    scanner_id: ClassVar[str] = "network-transit-gateway-cost-review"
    evidence_module: ClassVar[str] = "scanners.network.transit_gateway.evidence"
    evidence_type: ClassVar[str] = "TransitGatewayCostReviewEvidence"
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Reject unknown attachment types even in empty count-map containers."""
        if kind == "attachment_type":
            return isinstance(value, str) and value in RESOURCE_TYPES
        return super()._valid(value, kind, nullable=nullable)
