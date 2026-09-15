from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.core.error.helpers import (
    SERVICE_UNAVAILABLE_ERROR_MESSAGE_MARKERS,
)
from unio_collector.aws.core.error.policy import AwsErrorClassificationPolicy
from unio_collector.aws.service.unavailable_rule import ServiceUnavailableErrorRule

if TYPE_CHECKING:
    from unio_collector.aws.core.error.classification import AwsErrorClassification

SERVICE_UNAVAILABLE_ERROR_RULES = (
    ServiceUnavailableErrorRule(
        service_name="macie2",
        operation_name="GetMacieSession",
        error_codes=frozenset({"AccessDeniedException"}),
        message_markers=SERVICE_UNAVAILABLE_ERROR_MESSAGE_MARKERS,
        reason="macie_not_enabled",
    ),
    ServiceUnavailableErrorRule(
        service_name="securityhub",
        operation_name="DescribeHub",
        error_codes=frozenset({"InvalidAccessException"}),
        message_markers=SERVICE_UNAVAILABLE_ERROR_MESSAGE_MARKERS,
        reason="securityhub_not_enabled",
    ),
    ServiceUnavailableErrorRule(
        error_codes=frozenset({"AccessDeniedException", "InvalidAccessException"}),
        message_markers=SERVICE_UNAVAILABLE_ERROR_MESSAGE_MARKERS,
    ),
)

DEFAULT_ERROR_CLASSIFICATION_POLICY = AwsErrorClassificationPolicy(
    service_unavailable_rules=SERVICE_UNAVAILABLE_ERROR_RULES,
)


def classify_aws_error(  # noqa: D103
    error: Exception | None,
    *,
    service_name: str | None = None,
    operation_name: str | None = None,
) -> AwsErrorClassification:
    return DEFAULT_ERROR_CLASSIFICATION_POLICY.classify(
        error,
        service_name=service_name,
        operation_name=operation_name,
    )


def is_service_unavailable_error(  # noqa: D103
    error: Exception | None,
    *,
    service_name: str | None = None,
    operation_name: str | None = None,
) -> bool:
    return classify_aws_error(
        error,
        service_name=service_name,
        operation_name=operation_name,
    ).service_unavailable


def is_throttling_error(error: Exception | None) -> bool:  # noqa: D103
    return classify_aws_error(error).throttling


def is_permission_error(error: Exception | None) -> bool:  # noqa: D103
    return classify_aws_error(error).permission_denied


def is_unsupported_region_error(error: Exception | None) -> bool:  # noqa: D103
    return classify_aws_error(error).unsupported_region


def is_unsupported_operation_error(
    error: Exception | None,
    *,
    service_name: str | None = None,
    operation_name: str | None = None,
) -> bool:
    """Return whether a declared service operation is unavailable."""
    return (
        classify_aws_error(
            error,
            service_name=service_name,
            operation_name=operation_name,
        ).category
        == "unsupported_operation"
    )


def is_retryable_error(error: Exception | None) -> bool:  # noqa: D103
    return classify_aws_error(error).retryable


def is_expected_absence_error(error: Exception | None) -> bool:  # noqa: D103
    return classify_aws_error(error).expected_absence
