"""Explicit neutral network envelope fields and metadata vocabularies."""

from unio_collector.privacy.network.facts import NESTED_FIELDS, RESOURCE_FIELDS

VOCABULARIES = {
    "network_version": {"neutral-topology-v1"},
    "selection_version": {"network-whole-record-v1"},
    "relation_state": {"complete", "ambiguous"},
    "coverage_state": {"complete", "partial", "unavailable", "skipped", "capped"},
    "reason": {
        "api_failure",
        "api_denied",
        "unsupported_region_service",
        "pagination_cycle",
        "not_collected",
        "legacy_coverage_unknown",
        "topology_relation_unresolved",
        "evidence_omitted_by_bound",
    },
    "operation": {
        "",
        "DescribeAddresses",
        "DescribeVpcs",
        "DescribeRouteTables",
        "DescribeVpcEndpoints",
        "DescribeNatGateways",
        "DescribeNetworkInterfaces",
        "DescribeSubnets",
        "DescribeTransitGateways",
        "DescribeTransitGatewayAttachments",
        "DescribeTransitGatewayRouteTables",
        "DescribeVpcEndpointServiceConfigurations",
    },
    "resource_kind": set(RESOURCE_FIELDS),
}
FIELDS: dict[str, tuple[str, str, bool]] = {
    "": ("object", "safe_metadata", False),
    "regions": ("array", "region", False),
    "regions[]": ("string", "region", False),
    "network_evidence_version": ("network_version", "safe_metadata", True),
    "topology": ("array", "topology", False),
    "topology[]": ("object", "safe_metadata", False),
    "topology[].account_id": ("string", "aws_account_id", False),
    "topology[].region": ("string", "region", False),
    "topology[].resources": ("array", "safe_metadata", False),
    "topology[].resources[]": ("object", "safe_metadata", False),
    "topology[].resources[].kind": ("resource_kind", "safe_metadata", False),
    "topology[].resources[].identity": ("string", "network_identity", False),
    "topology[].resources[].observation_ordinal": ("count", "safe_metadata", False),
    "topology[].resources[].repeated_observation_ordinals": ("array", "safe_metadata", False),
    "topology[].resources[].repeated_observation_ordinals[]": ("count", "safe_metadata", False),
    "topology[].resources[].facts": ("object", "safe_metadata", False),
    "topology[].coverage": ("array", "safe_metadata", False),
    "topology[].coverage[]": ("object", "safe_metadata", False),
    "topology[].coverage[].account_id": ("string", "aws_account_id", False),
    "topology[].coverage[].region": ("string", "region", False),
    "topology[].coverage[].collection_name": ("resource_kind", "safe_metadata", False),
    "topology[].coverage[].operation": ("operation", "safe_metadata", False),
    "topology[].coverage[].state": ("coverage_state", "safe_metadata", False),
    "topology[].coverage[].enumeration_normal_termination": ("boolean", "safe_metadata", False),
    "topology[].coverage[].reason_codes": ("array", "safe_metadata", False),
    "topology[].coverage[].reason_codes[]": ("reason", "safe_metadata", False),
    "topology[].coverage[].failure_category": ("reason", "safe_metadata", True),
    "topology[].coverage[].failure_reference": ("string", "network_text", True),
    "topology[].relation_state": ("relation_state", "safe_metadata", False),
    "topology[].reason_codes": ("array", "safe_metadata", False),
    "topology[].reason_codes[]": ("reason", "safe_metadata", False),
    "topology[].selection_version": ("selection_version", "safe_metadata", False),
    "topology[].bound_hit": ("boolean", "safe_metadata", False),
    **{
        f"topology[].{key}": ("count", "safe_metadata", False)
        for key in (
            "byte_limit",
            "bytes_used",
            "resources_observed",
            "resources_retained",
            "resources_omitted",
            "relations_observed",
            "relations_retained",
            "relations_omitted",
        )
    },
    **{
        f"topology[].coverage[].{key}": ("count", "safe_metadata", False)
        for key in ("pages_observed", "resources_observed", "resources_retained", "resources_omitted")
    },
}
CATEGORIES = {
    "identifier": "resource_id",
    "identifiers": "resource_id",
    "region": "region",
    "service": "network_service",
    "timestamp": "timestamp",
    "text": "network_text",
    "ip": "ipv4",
    "account": "aws_account_id",
    "cidr": "cidr",
    "gateway": "network_gateway",
    "tag_key": "tag_key",
    "tag_value": "tag_value",
}


def fact_fields(fields: dict[str, str], prefix: str) -> dict[str, tuple[str, str, bool]]:
    """Flatten only declared fields for decisions after kind-specific preflight."""
    result = {}
    for key, spec in fields.items():
        path = prefix + "." + key
        if spec.startswith(("list:", "object:")):
            array = spec.startswith("list:")
            result[path] = ("array" if array else "object", "safe_metadata", True)
            if array:
                result[path + "[]"] = ("object", "safe_metadata", False)
            result.update(fact_fields(NESTED_FIELDS[spec.split(":", 1)[1]], path + ("[]" if array else "")))
        elif spec == "identifiers":
            result[path] = ("array", "safe_metadata", True)
            result[path + "[]"] = ("string", "resource_id", False)
        else:
            result[path] = ("boolean" if spec == "boolean" else "string", CATEGORIES.get(spec, "safe_metadata"), True)
    return result


for _fields in RESOURCE_FIELDS.values():
    FIELDS.update(fact_fields(_fields, "topology[].resources[].facts"))
