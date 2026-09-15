from __future__ import annotations  # noqa: D100

from typing import Any

from botocore.exceptions import ClientError

from unio_collector.aws import errors as aws_errors


def response_indicates_more_pages(response: dict[str, Any] | None) -> bool:  # noqa: D103
    if not response:
        return False
    for key in (
        "NextToken",
        "NextMarker",
        "NextContinuationToken",
        "NextPageToken",
        "LastEvaluatedKey",
        "LastEvaluatedTableName",
    ):
        if response.get(key):
            return True
    if response.get("IsTruncated") is True:
        return True
    return any(isinstance(value, dict) and response_indicates_more_pages(value) for value in response.values())


def event_source(service_name: str) -> str:  # noqa: D103
    return {
        "ce": "ce.amazonaws.com",
        "ec2": "ec2.amazonaws.com",
        "backup": "backup.amazonaws.com",
        "budgets": "budgets.amazonaws.com",
        "cloudtrail": "cloudtrail.amazonaws.com",
        "cloudfront": "cloudfront.amazonaws.com",
        "cloudwatch": "monitoring.amazonaws.com",
        "elbv2": "elasticloadbalancing.amazonaws.com",
        "freetier": "freetier.amazonaws.com",
        "iam": "iam.amazonaws.com",
        "lambda": "lambda.amazonaws.com",
        "logs": "logs.amazonaws.com",
        "pricing": "pricing.amazonaws.com",
        "rds": "rds.amazonaws.com",
        "resourcegroupstaggingapi": "tagging.amazonaws.com",
        "s3": "s3.amazonaws.com",
        "s3control": "s3-control.amazonaws.com",
        "service-quotas": "servicequotas.amazonaws.com",
        "sts": "sts.amazonaws.com",
        "xray": "xray.amazonaws.com",
    }.get(service_name, f"{service_name}.amazonaws.com")


def error_details(error: Exception | None) -> tuple[str | None, str | None, str | None]:  # noqa: D103
    if error is None:
        return None, None, None
    if isinstance(error, ClientError):
        response = error.response
        error_info = response.get("Error", {})
        metadata = response.get("ResponseMetadata", {})
        return (
            error_info.get("Code"),
            error_info.get("Message"),
            metadata.get("RequestId"),
        )
    return error.__class__.__name__, str(error), None


def sanitize_user_identity(identity: dict[str, Any]) -> dict[str, Any]:
    """Keep caller identity concise in the local API-call ledger."""
    allowed_keys = ("type", "Account", "Arn", "UserId", "account_id", "arn", "user_id")
    sanitized = {key: str(value) for key in allowed_keys if (value := identity.get(key)) not in (None, "")}
    return sanitized or {"type": "Unknown"}


def is_permission_error(error: Exception) -> bool:  # noqa: D103
    return aws_errors.is_permission_error(error)


def is_permission_error_code(code: str) -> bool:  # noqa: D103
    return aws_errors.is_permission_error_code(code)
