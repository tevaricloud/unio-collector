from __future__ import annotations  # noqa: D100

from botocore.exceptions import (
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.cache import (
    AwsScanCacheCancelledError,
    AwsScanCacheDeadlineExceededError,
    AwsScanCacheGenerationSupersededError,
    AwsScanCacheWaitTimeoutError,
    CacheFailureCategory,
    CacheFailureDecision,
    CacheFailureRetention,
)
from unio_collector.scan_workflow.scanner.runtime.cancellation_error import (
    ScannerDeadlineExceededError,
)


class AwsEvidenceCacheFailureClassifier:
    """Classify AWS evidence failures without coupling policy into the cache."""

    def classify(self, error: BaseException) -> CacheFailureDecision:
        """Retain only stable absence and permission outcomes for this scan."""
        category = self._classify_category(error)
        retention = (
            CacheFailureRetention.RETAIN
            if category
            in {
                CacheFailureCategory.EXPECTED_ABSENCE,
                CacheFailureCategory.PERMISSION_DENIED,
            }
            else CacheFailureRetention.EVICT
        )
        error_code = (
            getattr(error, "aws_error_code", None)
            or (aws_errors.get_aws_error_code(error) if isinstance(error, Exception) else None)
            or error.__class__.__name__
        )
        return CacheFailureDecision(
            category=category,
            retention=retention,
            error_code=str(error_code),
        )

    def _classify_category(self, error: BaseException) -> CacheFailureCategory:
        cached_category = getattr(error, "cache_failure_category", None)
        if cached_category:
            try:
                return CacheFailureCategory(str(cached_category))
            except ValueError:
                return CacheFailureCategory.INTERNAL_LOADER_ERROR
        runtime_category = self._classify_runtime_failure(error)
        if runtime_category is not None:
            return runtime_category
        if not isinstance(error, Exception):
            return CacheFailureCategory.INTERNAL_LOADER_ERROR
        return self._classify_aws_failure(error)

    def _classify_runtime_failure(
        self,
        error: BaseException,
    ) -> CacheFailureCategory | None:
        if isinstance(error, AwsScanCacheCancelledError):
            return CacheFailureCategory.CANCELLATION
        if isinstance(
            error,
            (
                AwsScanCacheDeadlineExceededError,
                AwsScanCacheWaitTimeoutError,
                ScannerDeadlineExceededError,
            ),
        ):
            return CacheFailureCategory.DEADLINE_EXPIRED
        if isinstance(error, AwsScanCacheGenerationSupersededError):
            return CacheFailureCategory.CANCELLATION
        if isinstance(error, PermissionError):
            return CacheFailureCategory.PERMISSION_DENIED
        if isinstance(
            error,
            (
                ConnectionClosedError,
                ConnectTimeoutError,
                EndpointConnectionError,
                ReadTimeoutError,
            ),
        ):
            return CacheFailureCategory.TRANSIENT_NETWORK
        return None

    def _classify_aws_failure(
        self,
        error: Exception,
    ) -> CacheFailureCategory:
        classification = aws_errors.classify_aws_error(error)
        if classification.service_unavailable:
            return CacheFailureCategory.SERVICE_UNAVAILABLE
        if classification.expected_absence:
            return CacheFailureCategory.EXPECTED_ABSENCE
        if classification.permission_denied:
            return CacheFailureCategory.PERMISSION_DENIED
        if classification.throttling:
            return CacheFailureCategory.THROTTLING
        response = getattr(error, "response", {})
        metadata = response.get("ResponseMetadata", {}) if isinstance(response, dict) else {}
        status_code = metadata.get("HTTPStatusCode") if isinstance(metadata, dict) else None
        if isinstance(status_code, int) and status_code >= 500:  # noqa: PLR2004
            return CacheFailureCategory.SERVICE_UNAVAILABLE
        return CacheFailureCategory.INTERNAL_LOADER_ERROR


def is_timeout_or_cancellation_failure(error: BaseException) -> bool:
    """Return whether a prefetch failure represents timeout or cancellation."""
    if isinstance(
        error,
        (
            AwsScanCacheCancelledError,
            AwsScanCacheDeadlineExceededError,
            AwsScanCacheGenerationSupersededError,
            AwsScanCacheWaitTimeoutError,
            ConnectTimeoutError,
            ReadTimeoutError,
            ScannerDeadlineExceededError,
        ),
    ):
        return True
    return getattr(error, "cache_failure_category", None) in {
        "cancellation",
        "deadline_expired",
    }
