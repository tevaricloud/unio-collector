from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.core.error.classification import AwsErrorClassification
from unio_collector.aws.core.error.helpers import (
    EXPECTED_ABSENCE_ERROR_CODES,
    THROTTLE_ERROR_CODES,
    UNSUPPORTED_REGION_ERROR_CODES,
    AwsErrorCategory,
    get_aws_error_code,
    get_aws_error_message,
    is_permission_error_code,
)

if TYPE_CHECKING:
    from unio_collector.aws.service.unavailable_rule import ServiceUnavailableErrorRule


class AwsErrorClassificationPolicy:  # noqa: D101
    def __init__(  # noqa: D107
        self,
        service_unavailable_rules: tuple[ServiceUnavailableErrorRule, ...],
    ) -> None:
        self._service_unavailable_rules = service_unavailable_rules

    def classify(  # noqa: D102
        self,
        error: Exception | None,
        *,
        service_name: str | None = None,
        operation_name: str | None = None,
    ) -> AwsErrorClassification:
        code = get_aws_error_code(error)
        message = get_aws_error_message(error)
        normalized_message = message.lower()
        if error is None:
            return AwsErrorClassification(
                code=None,
                message="",
                category="none",
                expected_absence=False,
                service_unavailable=False,
                permission_denied=False,
                throttling=False,
                unsupported_region=False,
                retryable=False,
            )
        cached_category = str(
            getattr(error, "cache_failure_category", ""),
        )
        if cached_category:
            return self._classify_cached_failure(
                code=code,
                message=message,
                category=cached_category,
            )
        service_unavailable_reason = self._get_service_unavailable_reason(
            code=code or "",
            message=normalized_message,
            service_name=service_name,
            operation_name=operation_name,
        )
        if service_unavailable_reason is not None:
            return AwsErrorClassification(
                code=code,
                message=message,
                category="service_unavailable",
                expected_absence=True,
                service_unavailable=True,
                permission_denied=False,
                throttling=False,
                unsupported_region=False,
                retryable=False,
                reason=service_unavailable_reason,
                service_availability_status="not_enabled_or_unavailable",
            )
        if code and code in EXPECTED_ABSENCE_ERROR_CODES:
            return AwsErrorClassification(
                code=code,
                message=message,
                category="expected_absence",
                expected_absence=True,
                service_unavailable=False,
                permission_denied=False,
                throttling=False,
                unsupported_region=False,
                retryable=False,
                reason="expected_absence",
            )
        unsupported_operation = self._is_unsupported_operation(
            code=code or "",
            message=normalized_message,
            service_name=service_name,
            operation_name=operation_name,
        )
        throttling = code in THROTTLE_ERROR_CODES or "throttl" in (code or "").lower()
        unsupported_region = bool(code and code in UNSUPPORTED_REGION_ERROR_CODES)
        permission_denied = bool(code and is_permission_error_code(code))
        if permission_denied:
            category: AwsErrorCategory = "permission_denied"
        elif throttling:
            category = "throttling"
        elif unsupported_operation:
            category = "unsupported_operation"
        elif unsupported_region:
            category = "unsupported_region"
        else:
            category = "failure"
        return AwsErrorClassification(
            code=code,
            message=message,
            category=category,
            expected_absence=False,
            service_unavailable=False,
            permission_denied=permission_denied,
            throttling=throttling,
            unsupported_region=unsupported_region,
            retryable=throttling or unsupported_region,
            reason="unsupported_operation" if unsupported_operation else None,
        )

    def _classify_cached_failure(
        self,
        *,
        code: str | None,
        message: str,
        category: str,
    ) -> AwsErrorClassification:
        expected_absence = category == "expected_absence"
        service_unavailable = category == "service_unavailable"
        permission_denied = category == "permission_denied"
        throttling = category == "throttling"
        if expected_absence:
            aws_category: AwsErrorCategory = "expected_absence"
        elif service_unavailable:
            aws_category = "service_unavailable"
        elif permission_denied:
            aws_category = "permission_denied"
        elif throttling:
            aws_category = "throttling"
        else:
            aws_category = "failure"
        return AwsErrorClassification(
            code=code,
            message=message,
            category=aws_category,
            expected_absence=expected_absence,
            service_unavailable=service_unavailable,
            permission_denied=permission_denied,
            throttling=throttling,
            unsupported_region=False,
            retryable=category
            in {
                "throttling",
                "service_unavailable",
                "transient_network",
                "cancellation",
                "deadline_expired",
                "internal_loader_error",
            },
            reason="expected_absence" if expected_absence else None,
            service_availability_status=("not_enabled_or_unavailable" if service_unavailable else "unknown"),
        )

    def _is_unsupported_operation(
        self,
        *,
        code: str,
        message: str,
        service_name: str | None,
        operation_name: str | None,
    ) -> bool:
        if service_name != "bedrock" or operation_name != "ListCustomModels":
            return False
        if code == "UnknownOperationException":
            return True
        return code == "ValidationException" and "unknown operation" in message

    def _get_service_unavailable_reason(
        self,
        *,
        code: str,
        message: str,
        service_name: str | None,
        operation_name: str | None,
    ) -> str | None:
        for rule in self._service_unavailable_rules:
            if rule.matches(
                code=code,
                message=message,
                service_name=service_name,
                operation_name=operation_name,
            ):
                return rule.reason
        return None
