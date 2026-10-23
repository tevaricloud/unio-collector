"""Independent complete field inventory of actual regional DynamoDB observations."""

from unio_collector.privacy.analytics.fields import names_and_counts
from unio_collector.privacy.platform.fields import COMMON
from unio_collector.privacy.s3.fields import fields

SCANNER = "dynamodb-cost-governance-review"
COUNTS = (
    "table_count active_table_count pay_per_request_table_count provisioned_table_count standard_ia_table_count "
    "stream_enabled_table_count pitr_enabled_table_count pitr_disabled_table_count ttl_enabled_table_count "
    "ttl_disabled_table_count global_secondary_index_count provisioned_global_secondary_index_count "
    "provisioned_table_without_autoscaling_count provisioned_gsi_without_autoscaling_count "
    "total_provisioned_read_capacity total_provisioned_write_capacity autoscaling_target_count "
    "autoscaling_policy_count tagged_table_count untagged_table_count metric_table_count metric_observation_count "
    "consumed_capacity_table_count throttle_signal_table_count system_error_signal_table_count"
)
NAMES = (
    "sample_table_names sample_pay_per_request_tables sample_provisioned_tables sample_standard_ia_tables "
    "sample_stream_enabled_tables sample_pitr_enabled_tables sample_pitr_disabled_tables sample_ttl_enabled_tables "
    "sample_ttl_disabled_tables sample_provisioned_tables_without_autoscaling "
    "sample_provisioned_gsis_without_autoscaling sample_untagged_tables sample_metric_table_names"
)
METRICS = frozenset(
    {
        "ConsumedReadCapacityUnits",
        "ConsumedWriteCapacityUnits",
        "ReadThrottleEvents",
        "WriteThrottleEvents",
        "ThrottledRequests",
        "SystemErrors",
        "SuccessfulRequestLatency",
    }
)
FIELDS = {
    **COMMON,
    **names_and_counts(COUNTS, NAMES),
    **fields("records[].table_detail_collected", "boolean"),
    **fields("records[].sample_tag_keys", "array", "tag_key"),
    **fields("records[].sample_tag_keys[]", "string", "tag_key"),
    **fields("records[].observed_metric_names", "array", "free_text"),
    **fields("records[].observed_metric_names[]", "string", "free_text"),
    **fields("records[].average_daily_read_capacity_units records[].average_daily_write_capacity_units", "money", "summary_count", nullable=True),
}
