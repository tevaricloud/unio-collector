from __future__ import annotations  # noqa: D104

# pyright: reportUnsupportedDunderAll=false
from importlib import import_module
from typing import Any

from unio_collector.aws.audit.api_safety import (
    READ_ONLY_OPERATION_ALLOWLIST,
    READ_ONLY_OPERATION_PREFIXES,
    AwsOperationSafetyClassification,
    classify_aws_operation,
    classify_operation_read_only,
)
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.audit.errors import UndeclaredAwsOperationError
from unio_collector.aws.audit.events import (
    error_details,
    event_source,
    is_permission_error,
    is_permission_error_code,
    response_indicates_more_pages,
    sanitize_user_identity,
)
from unio_collector.aws.audit.operation_names import (
    get_api_operation_name,
    snake_to_pascal,
)
from unio_collector.aws.audit.redaction import (
    ACCOUNT_ID_TEXT_PATTERN,
    ARN_TEXT_PATTERN,
    CONTEXTUAL_REQUEST_KEYS,
    IPV4_TEXT_PATTERN,
    RESOURCE_ID_TEXT_PATTERN,
    SENSITIVE_REQUEST_KEYS,
    AuditLedgerRedactionPolicy,
    normalize_request_key,
    redact_contextual_value,
    redact_request_parameters,
    redact_sensitive_text,
    redact_text_values,
)
from unio_collector.aws.audit.response_counts import (
    AwsResponseResultCounts,
    count_cloudfront_results,
    count_cost_explorer_cost_rows,
    count_cost_explorer_results,
    count_pricing_results,
    count_response_list_items,
    count_response_results,
)
from unio_collector.aws.audit.unsafe_error import UnsafeAwsOperationError
from unio_collector.aws.audited.client import AuditedAwsClient
from unio_collector.aws.audited.paginator import AuditedAwsPaginator
from unio_collector.aws.audited.session import AuditedAwsSession

__all__ = [
    "ACCOUNT_ID_TEXT_PATTERN",
    "ARN_TEXT_PATTERN",
    "CONTEXTUAL_REQUEST_KEYS",
    "IPV4_TEXT_PATTERN",
    "READ_ONLY_OPERATION_ALLOWLIST",
    "READ_ONLY_OPERATION_PREFIXES",
    "RESOURCE_ID_TEXT_PATTERN",
    "SENSITIVE_REQUEST_KEYS",
    "ApiCallLedger",
    "AuditLedgerRedactionPolicy",
    "AuditedAwsClient",
    "AuditedAwsPaginator",
    "AuditedAwsSession",
    "AwsAuditContext",
    "AwsOperationSafetyClassification",
    "AwsResponseResultCounts",
    "UndeclaredAwsOperationError",
    "UnsafeAwsOperationError",
    "classify_aws_operation",
    "classify_operation_read_only",
    "count_cloudfront_results",
    "count_cost_explorer_cost_rows",
    "count_cost_explorer_results",
    "count_pricing_results",
    "count_response_list_items",
    "count_response_results",
    "error_details",
    "event_source",
    "get_api_operation_name",
    "is_permission_error",
    "is_permission_error_code",
    "normalize_request_key",
    "redact_contextual_value",
    "redact_request_parameters",
    "redact_sensitive_text",
    "redact_text_values",
    "response_indicates_more_pages",
    "sanitize_user_identity",
    "snake_to_pascal",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    if name == "ApiCallLedger":
        return import_module("unio_collector.aws.api.call_ledger").ApiCallLedger
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
