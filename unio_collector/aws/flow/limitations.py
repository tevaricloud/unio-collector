"""Structured collection reasons; presentation belongs to analysis."""

NOT_RETAINED_FIELDS = (
    "srcport",
    "dstport",
    "protocol",
    "interface_id",
    "start",
    "end",
    "direction",
)
FLOW_REASON_CODES = frozenset(
    {
        "unsupported_destination",
        "unsupported_format",
        "query_failure",
        "query_result_limit_reached",
        "definition_cap_reached",
        "continuation_not_followed",
        "address_unresolved",
        "ambiguous_address",
        "route_context_incomplete",
        "topology_evidence_omitted_by_bound",
        "fields_not_retained_by_pair_aggregation",
    }
)
