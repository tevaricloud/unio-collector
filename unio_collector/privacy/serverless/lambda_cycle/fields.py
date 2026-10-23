"""Explicit actual Lambda inventory, notification, configuration and summary paths."""

from __future__ import annotations

from unio_collector.privacy.s3.fields import fields
from unio_collector.privacy.serverless.metric import METRIC_FIELDS

NOTIFICATION = "records[].s3_notifications[]"
EVENT = "records[].event_sources[]"
SUMMARY = "metadata.collection_summary."
S3_SUMMARY = "metadata.s3_notification_scan_summary."
FIELDS = {
    "": ("object", "safe_metadata", False),
    **fields("records regions", "array"),
    **fields("records[] metadata metadata.collection_summary metadata.s3_notification_scan_summary", "object"),
    **fields("regions[] records[].region", "string", "region"),
    **fields("records[].function_name", "string", "resource_name"),
    **fields("records[].function_arn", "string", "arn"),
    **fields("records[].account_id", "string", "aws_account_id"),
    **fields("records[].runtime", "string", "resource_name", nullable=True),
    **fields(
        "records[].memory_mb records[].timeout_seconds records[].reserved_concurrency records[].provisioned_concurrency",
        "count",
        "summary_count",
        nullable=True,
    ),
    **fields("records[].architectures records[].event_sources records[].s3_notifications records[].collection_errors", "array"),
    **fields("records[].architectures[]", "lambda_architecture"),
    **fields("records[].derived_metric_policy_fields_populated", "boolean"),
    **fields("records[].environment_bucket_match", "boolean", nullable=True),
    **fields("records[].destination_config records[].destination_config.OnSuccess records[].destination_config.OnFailure", "object"),
    **fields("records[].destination_config.OnSuccess.Destination records[].destination_config.OnFailure.Destination", "string", "arn"),
    **fields("records[].environment_variables", "string_map", "free_text"),
    **fields("records[].tags records[].tag_evidence.tags", "string_map", "tag_value"),
    **fields("records[].tag_evidence", "object", nullable=True),
    **fields("records[].tag_evidence.state", "lambda_tag_state"),
    **fields("records[].tag_evidence.limitation", "string", "free_text", nullable=True),
    **fields("records[].collection_errors[]", "lambda_configuration_error"),
    **fields(NOTIFICATION + " " + EVENT + " " + NOTIFICATION + ".filter_rules[]", "object"),
    **fields(NOTIFICATION + ".bucket_name", "string", "bucket_name"),
    **fields(NOTIFICATION + ".lambda_function_arn", "string", "arn"),
    **fields(NOTIFICATION + ".events " + NOTIFICATION + ".filter_rules", "array"),
    **fields(NOTIFICATION + ".events[]", "lambda_s3_event"),
    **fields(NOTIFICATION + ".filter_rules[].name", "lambda_filter_name"),
    **fields(NOTIFICATION + ".filter_rules[].value", "string", "free_text"),
    **fields(EVENT + ".source_type", "string", "resource_name"),
    **fields(EVENT + ".source_arn", "string", "arn", nullable=True),
    **fields(EVENT + ".uuid", "string", "resource_id", nullable=True),
    **fields(EVENT + ".state", "string", "free_text", nullable=True),
    **fields(EVENT + ".batch_size", "count", "summary_count", nullable=True),
    **fields("metadata.collect_tags", "boolean"),
    **fields(SUMMARY + "s3_notification_detail_mode " + S3_SUMMARY + "notification_detail_mode", "lambda_detail_mode"),
    **fields(
        " ".join(
            SUMMARY + key for key in ("bucket_population_count", "bucket_notifications_attempted", "notification_success_count", "notification_failure_count")
        ),
        "count",
        "summary_count",
    ),
    **fields(
        " ".join(
            SUMMARY + key
            for key in (
                "bucket_population_known",
                "collection_complete",
                "collection_capped",
                "collection_partial",
                "collection_unavailable",
                "detail_intentionally_skipped",
            )
        ),
        "boolean",
    ),
    **fields(SUMMARY + "operational_bucket_cap " + S3_SUMMARY + "max_s3_buckets", "count", "summary_count", nullable=True),
    **fields(SUMMARY + "limitations", "array"),
    **fields(SUMMARY + "limitations[]", "string", "free_text"),
    **fields(
        " ".join(
            S3_SUMMARY + key
            for key in (
                "candidate_bucket_count",
                "checked_bucket_count",
                "skipped_bucket_count",
                "worker_count",
                "notification_read_error_count",
                "policy_scan_max_functions",
                "policy_function_count",
                "policy_candidate_bucket_count",
                "policy_read_error_count",
                "policy_baseline_bucket_check_count",
                "policy_minimum_bucket_check_count",
            )
        ),
        "count",
        "summary_count",
    ),
    **fields(S3_SUMMARY + "limited", "boolean"),
    **fields(S3_SUMMARY + "bucket_index_source", "lambda_bucket_source"),
    **fields(S3_SUMMARY + "selection_mode", "lambda_selection_mode"),
    **fields(S3_SUMMARY + "policy_scan_skipped_reason", "lambda_policy_skip", nullable=True),
    **METRIC_FIELDS,
}
