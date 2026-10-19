"""Closed PrivateLink regional observations and neutral endpoint topology."""

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
            "interface_endpoint_count",
            "gateway_load_balancer_endpoint_count",
            "available_endpoint_count",
            "pending_endpoint_count",
            "tagged_endpoint_count",
            "endpoint_service_count",
        )
    },
    **{
        f"records[].{key}": ("array", "safe_metadata", False)
        for key in ("endpoint_service_names", "sample_endpoint_ids", "sample_vpc_ids", "sample_service_names")
    },
    **{f"records[].{key}[]": ("string", "resource_id", False) for key in ("sample_endpoint_ids", "sample_vpc_ids")},
    **{f"records[].{key}[]": ("string", "network_service", False) for key in ("endpoint_service_names", "sample_service_names")},
}


class PrivateLinkPrivacyContract(NetworkPrivacyContract):
    """Bind endpoint facts and factual counts to their exact AWS producer."""

    collection_names: ClassVar[frozenset[str]] = frozenset({"vpc_endpoints", "vpc_endpoint_service_configurations"})
    scanner_id: ClassVar[str] = "network-privatelink-cost-review"
    evidence_module: ClassVar[str] = "scanners.network.privatelink.evidence"
    evidence_type: ClassVar[str] = "PrivateLinkCostReviewEvidence"
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS
