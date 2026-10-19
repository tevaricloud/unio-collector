"""Complete current neutral-pair flow root, query, period and topology field contract."""

from unio_collector.privacy.flow.record_fields import FIELDS as RECORD_FIELDS
from unio_collector.privacy.flow.topology_fields import FIELDS as TOPOLOGY_FIELDS
from unio_collector.privacy.s3.fields import fields

FIELDS = {
    "": ("object", "safe_metadata", False),
    **fields("collector", "nil", nullable=True),
    **fields("records regions", "array"),
    **fields("regions[]", "string", "region"),
    **fields("metadata query_options", "object"),
    **fields("scan_period", "object", nullable=True),
    **RECORD_FIELDS,
    **TOPOLOGY_FIELDS,
    **fields("metadata.flow_evidence_version", "flow_version"),
    **fields("metadata.flow_logs_discovered", "count", "summary_count"),
    **fields(
        (
            "metadata.queried_log_groups metadata.query_errors metadata.enrichment_errors "
            "metadata.route_table_enrichment_errors metadata.reason_codes metadata.queries "
            "metadata.not_retained_fields"
        ),
        "array",
    ),
    **fields("metadata.queried_log_groups[]", "string", "resource_name"),
    **fields("metadata.query_errors[] metadata.enrichment_errors[] metadata.route_table_enrichment_errors[]", "string", "free_text"),
    **fields("metadata.collection_state", "collection_state"),
    **fields("metadata.reason_codes[]", "reason"),
    **fields("metadata.not_retained_fields[]", "not_retained"),
    **fields("metadata.field_retention_reason", "retention_reason"),
    **fields("metadata.format_scope", "format_scope"),
    **fields("metadata.queries[] metadata.topology", "object"),
    **fields("metadata.queries[].region", "string", "region"),
    **fields("metadata.queries[].flow_log_id metadata.queries[].log_group_name", "string", "resource_id"),
    **fields("metadata.queries[].start metadata.queries[].end", "timestamp", "timestamp"),
    **fields("metadata.queries[].result_limit metadata.queries[].records_returned", "count", "summary_count"),
    **fields("metadata.queries[].state", "query_state"),
    **fields("metadata.queries[].reasons", "array"),
    **fields("metadata.queries[].reasons[]", "reason"),
    **fields("metadata.queries[].selection", "query_selection"),
    **fields("metadata.queries[].grouping", "grouping"),
    **fields("metadata.queries[].grouping[]", "grouping_name"),
    **fields("metadata.queries[].action_filter", "action_filter"),
    **fields("query_options.max_log_groups query_options.query_limit query_options.max_query_polls", "positive_count", "summary_count"),
    **fields("query_options.poll_seconds query_options.query_timeout_seconds", "positive_number"),
    **fields("scan_period.kind", "period_kind"),
    **fields("scan_period.raw_input", "object"),
    **fields(
        (
            "scan_period.current_start_date scan_period.current_end_date scan_period.previous_start_date "
            "scan_period.previous_end_date scan_period.raw_input.date_from scan_period.raw_input.date_to"
        ),
        "timestamp",
        "timestamp",
    ),
    **fields("scan_period.raw_input.days scan_period.raw_input.months scan_period.raw_input.years", "positive_count", "summary_count"),
}
