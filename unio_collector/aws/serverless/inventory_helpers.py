from __future__ import annotations  # noqa: D100

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.s3.lambda_notification import S3LambdaNotificationRecord

S3_NOTIFICATION_DETAIL_MODES = {"full", "summary"}


def function_name_from_arn(value: str | None) -> str | None:  # noqa: D103
    if not value:
        return None
    return value.rsplit(":", 1)[-1]


def group_s3_notifications_by_function(  # noqa: D103
    notifications: list[S3LambdaNotificationRecord],
) -> dict[str, list[S3LambdaNotificationRecord]]:
    grouped: dict[str, list[S3LambdaNotificationRecord]] = {}
    for notification in notifications:
        grouped.setdefault(notification.lambda_function_arn, []).append(notification)
    return grouped


def event_source_type(value: str | None) -> str:  # noqa: D103
    if not value:
        return "unknown"
    if ":sqs:" in value:
        return "sqs"
    if ":dynamodb:" in value:
        return "dynamodb"
    if ":kinesis:" in value:
        return "kinesis"
    return "unknown"


def extract_s3_filter_rules(config: dict[str, object]) -> list[dict[str, str]]:  # noqa: D103
    filter_config = object_mapping(config.get("Filter", {}))
    key_config = object_mapping(filter_config.get("Key", {}))
    rules = key_config.get("FilterRules", [])
    if not isinstance(rules, list):
        return []
    return [{"name": str(rule.get("Name", "")), "value": str(rule.get("Value", ""))} for rule in rules if isinstance(rule, dict)]


def extract_s3_bucket_names_from_lambda_policy(policy_text: str) -> set[str]:  # noqa: D103
    if not policy_text:
        return set()
    try:
        policy = json.loads(policy_text)
    except json.JSONDecodeError:
        return set()
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return set()
    bucket_names: set[str] = set()
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        if not statement_allows_s3_service(statement):
            continue
        bucket_names.update(
            extract_s3_bucket_names_from_source_arns(
                extract_lambda_policy_source_arns(statement),
            ),
        )
    return bucket_names


def statement_allows_s3_service(statement: dict[str, object]) -> bool:  # noqa: D103
    principal = statement.get("Principal")
    if isinstance(principal, str):
        return principal == "s3.amazonaws.com"
    if not isinstance(principal, dict):
        return False
    service = principal.get("Service")
    if isinstance(service, str):
        return service == "s3.amazonaws.com"
    if isinstance(service, list):
        return "s3.amazonaws.com" in [str(item) for item in service]
    return False


def extract_lambda_policy_source_arns(statement: dict[str, object]) -> list[str]:  # noqa: D103
    condition = statement.get("Condition", {})
    if not isinstance(condition, dict):
        return []
    arns: list[str] = []
    for condition_value in condition.values():
        if not isinstance(condition_value, dict):
            continue
        for key, value in condition_value.items():
            if str(key).lower() != "aws:sourcearn":
                continue
            if isinstance(value, str):
                arns.append(value)
            elif isinstance(value, list):
                arns.extend(str(item) for item in value)
    return arns


def extract_s3_bucket_names_from_source_arns(source_arns: list[str]) -> set[str]:  # noqa: D103
    bucket_names: set[str] = set()
    for source_arn in source_arns:
        if ":s3:::" not in source_arn:
            continue
        bucket_name = source_arn.split(":s3:::", 1)[1].split("/", 1)[0]
        if bucket_name:
            bucket_names.add(bucket_name)
    return bucket_names


def optional_str(value: object) -> str | None:  # noqa: D103
    if value in (None, ""):
        return None
    return str(value)


def normalized_s3_bucket_region(bucket: dict[str, object]) -> str | None:  # noqa: D103
    region = optional_str(bucket.get("BucketRegion"))
    if region == "EU":
        return "eu-west-1"
    return region


def optional_int_value(value: object) -> int | None:  # noqa: D103
    if value in (None, ""):
        return None
    try:
        return int(str(value))
    except Exception:  # noqa: BLE001
        return None


def string_list(value: object) -> list[str]:  # noqa: D103
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def object_mapping(value: object) -> dict[str, object]:  # noqa: D103
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items()}


def string_mapping(value: object) -> dict[str, str]:  # noqa: D103
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def normalize_s3_notification_detail_mode(value: object) -> str:  # noqa: D103
    normalized = str(value or "full").strip().lower()
    if normalized in S3_NOTIFICATION_DETAIL_MODES:
        return normalized
    allowed = ", ".join(sorted(S3_NOTIFICATION_DETAIL_MODES))
    msg = f"Lambda s3_notification_detail_mode must be one of {allowed}; got {value!r}."
    raise ValueError(
        msg,
    )
