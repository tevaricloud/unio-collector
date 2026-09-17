from __future__ import annotations  # noqa: D100

from typing import Literal

from botocore.exceptions import ClientError

THROTTLE_ERROR_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "ThrottledException",
        "TooManyRequestsException",
        "RequestLimitExceeded",
        "RequestThrottled",
        "RequestThrottledException",
        "LimitExceededException",
        "SlowDown",
    },
)

PERMISSION_ERROR_MARKERS = frozenset(
    {
        "accessdenied",
        "unauthorized",
        "unrecognizedclient",
        "invalidclienttoken",
    },
)

UNSUPPORTED_REGION_ERROR_CODES = frozenset(
    {
        "OptInRequired",
        "AuthFailure",
        "InvalidClientTokenId",
        "InvalidAction",
        "UnsupportedOperation",
        "UnsupportedRegion",
    },
)

EXPECTED_ABSENCE_ERROR_CODES = frozenset(
    {
        "DataUnavailableException",
        "InsightNotEnabledException",
        "NoSuchBucketPolicy",
        "NoSuchLifecycleConfiguration",
        "NoSuchPublicAccessBlockConfiguration",
        "NoSuchTagSet",
        "NoSuchEntity",
        "TrailNotFoundException",
        "ReplicationConfigurationNotFoundError",
        "ResourceNotFoundException",
        "WAFNonexistentItemException",
    },
)

SERVICE_UNAVAILABLE_ERROR_MESSAGE_MARKERS = frozenset(
    {
        "is not enabled",
        "not enabled",
        "not subscribed",
        "not opted in",
    },
)

AwsErrorCategory = Literal[
    "none",
    "expected_absence",
    "service_unavailable",
    "permission_denied",
    "throttling",
    "unsupported_operation",
    "unsupported_region",
    "failure",
]

ServiceAvailabilityStatus = Literal[
    "unknown",
    "not_enabled_or_unavailable",
]


def get_aws_error_code(error: Exception | None) -> str | None:  # noqa: D103
    if error is None:
        return None
    cached_code = getattr(error, "aws_error_code", None)
    if cached_code:
        return str(cached_code)
    if isinstance(error, ClientError):
        return str(error.response.get("Error", {}).get("Code") or "")
    return error.__class__.__name__


def get_aws_error_message(error: Exception | None) -> str:  # noqa: D103
    if error is None:
        return ""
    if isinstance(error, ClientError):
        return str(error.response.get("Error", {}).get("Message") or "")
    return str(error)


def is_permission_error_code(code: str) -> bool:  # noqa: D103
    normalized = code.lower()
    return any(marker in normalized for marker in PERMISSION_ERROR_MARKERS)


def is_expected_absence_error_code(code: str) -> bool:  # noqa: D103
    return code in EXPECTED_ABSENCE_ERROR_CODES
