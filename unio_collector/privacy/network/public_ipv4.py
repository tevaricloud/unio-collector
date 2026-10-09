"""Closed regional public IPv4 counts and neutral topology privacy contract."""

from typing import ClassVar

from unio_collector.privacy.network.base import NetworkPrivacyContract
from unio_collector.privacy.network.fields import FIELDS as TOPOLOGY_FIELDS

FIELDS = {
    **TOPOLOGY_FIELDS,
    "records": ("array", "safe_metadata", False),
    "records[]": ("object", "safe_metadata", False),
    "records[].account_id": ("string", "aws_account_id", False),
    "records[].region": ("string", "region", False),
    **{
        f"records[].{key}": ("count", "safe_metadata", False)
        for key in (
            "elastic_ip_count",
            "attached_elastic_ip_count",
            "unattached_elastic_ip_count",
            "eni_public_ip_count",
            "auto_assigned_public_ip_count",
            "tagged_address_count",
        )
    },
    **{f"records[].{key}": ("array", "safe_metadata", False) for key in ("allocation_ids", "sample_interface_ids")},
    **{f"records[].{key}[]": ("string", "resource_id", False) for key in ("allocation_ids", "sample_interface_ids")},
}


class PublicIpv4PrivacyContract(NetworkPrivacyContract):
    """Bind explicit record fields to the existing regional IPv4 scanner."""

    collection_names: ClassVar[frozenset[str]] = frozenset({"addresses", "network_interfaces"})
    scanner_id: ClassVar[str] = "network-public-ipv4-review"
    evidence_module: ClassVar[str] = "scanners.network.public_ipv4.evidence"
    evidence_type: ClassVar[str] = "PublicIpv4Evidence"
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS
