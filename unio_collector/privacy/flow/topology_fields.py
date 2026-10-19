"""Closed topology schemas expanded over finite pinned SDK region keys, never input keys."""

from unio_collector.privacy.flow.vocabulary import REGIONS
from unio_collector.privacy.s3.fields import fields

ROOT = {
    "": ("object", "safe_metadata", False),
    **fields("state", "topology_state"),
    **fields("reason_codes facts", "array"),
    **fields("reason_codes[]", "reason"),
    **fields("facts[]", "object"),
    **fields("budget_bytes bytes_used facts_retained facts_omitted", "count", "summary_count"),
    **fields("bound_hit", "boolean"),
    **fields("selection", "topology_selection"),
    **fields("route_scope", "route_scope"),
}
INTERFACE = {
    "": ("object", "safe_metadata", False),
    **fields("kind", "interface_kind"),
    **fields("eni_id vpc_id subnet_id attachment_instance_id", "string", "resource_id", nullable=True),
    **fields("resource_owner_id", "string", "aws_account_id", nullable=True),
    **fields("availability_zone", "string", "region", nullable=True),
    **fields("description", "string", "free_text", nullable=True),
    **fields("interface_type", "interface_type", nullable=True),
    **fields("private_dns_name", "string", "resource_name", nullable=True),
    **fields("attribution_tags", "tag_map", "tag_value"),
    **fields("attribution_tags.0", "string", "tag_value"),
    **fields("private_addresses", "array"),
    **fields("private_addresses[]", "string", "network_identity"),
}
ROUTE = {
    "": ("object", "safe_metadata", False),
    **fields("kind", "route_kind"),
    **fields("route_table_id", "string", "resource_id"),
    **fields("vpc_id", "string", "resource_id", nullable=True),
    **fields("destination", "string", "network_identity", nullable=True),
    **fields("address_family", "address_family"),
    **fields("state", "route_state", nullable=True),
    **fields("origin", "route_origin", nullable=True),
    **fields("targets associations", "array"),
    **fields("targets[] associations[]", "pair"),
    **fields("targets[][0]", "target_key"),
    **fields("targets[][1]", "string", "arn_or_name"),
    **fields("associations[][0]", "string", "resource_id"),
    **fields("associations[][1]", "association"),
}


def scoped(specs: dict[str, tuple[str, str, bool]], *, facts: bool = False) -> dict[str, tuple[str, str, bool]]:
    """Expand only declared fields over independently pinned public region names."""
    return {
        "metadata.topology." + region + (".facts[]" if facts else "") + ("." + path if path else ""): spec for region in REGIONS for path, spec in specs.items()
    }


INTERFACE_FIELDS = scoped(INTERFACE, facts=True)
ROUTE_FIELDS = scoped(ROUTE, facts=True)
FIELDS = {**scoped(ROOT), **INTERFACE_FIELDS, **ROUTE_FIELDS}
FACT_PATHS = frozenset("metadata.topology." + region + ".facts[]" for region in REGIONS)
TARGET_PAIRS = frozenset(path + ".targets[]" for path in FACT_PATHS)
ASSOCIATION_PAIRS = frozenset(path + ".associations[]" for path in FACT_PATHS)
