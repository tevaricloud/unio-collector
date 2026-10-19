"""Finite actual Lambda/S3 producer controls, distinct from arbitrary customer labels."""

from __future__ import annotations

from functools import lru_cache

from botocore.loaders import Loader

VOCABULARIES = {
    "lambda_architecture": {"arm64", "x86_64"},
    "lambda_filter_name": {"prefix", "suffix"},
    "lambda_tag_state": {"known", "unavailable", "not_collected"},
    "lambda_detail_mode": {"full", "summary"},
    "lambda_bucket_source": {"direct_list_buckets", "shared_s3_bucket_index", "not_collected"},
    "lambda_selection_mode": {"bucket_cap", "shared_bucket_index_cap", "direct_bucket_cap", "bucket_inventory_unavailable", "summary_skipped"},
    "lambda_policy_skip": {"compatibility_option_not_applied", "skipped_by_notification_detail_mode"},
    "lambda_configuration_error": {"GetFunctionConfiguration:UnavailableEvidence", "GetFunctionEventInvokeConfig:UnavailableEvidence"},
}
SOURCE_TYPES = frozenset({"sqs", "dynamodb", "kinesis", "kafka", "mq", "docdb", "unknown"})


@lru_cache(maxsize=1)
def s3_events() -> frozenset[str]:
    """Read the local SDK's finite event vocabulary without a client or network access."""
    return frozenset(Loader().load_service_model("s3", "service-2")["shapes"]["Event"]["enum"])
