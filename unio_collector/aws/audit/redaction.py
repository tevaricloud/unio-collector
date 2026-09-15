from __future__ import annotations  # noqa: D100

import re
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Any, cast

SENSITIVE_REQUEST_KEYS = (
    "token",
    "password",
    "secret",
    "credential",
    "authorization",
    "accesskey",
    "externalid",
)

CONTEXTUAL_REQUEST_KEYS = {
    "accountid",
    "allocationid",
    "allocationids",
    "arn",
    "arns",
    "budgetname",
    "functionname",
    "instanceid",
    "instanceids",
    "loadbalancerarns",
    "loggroupname",
    "queueurl",
    "resourcearn",
    "resourcearns",
    "resourceid",
    "resourceids",
    "snapshotid",
    "snapshotids",
    "trailname",
    "volumeid",
    "volumeids",
}

ACCOUNT_ID_TEXT_PATTERN = re.compile(r"\b\d{12}\b")
ARN_TEXT_PATTERN = re.compile(r"\barn:aws[a-z-]*:[^\s,)\]]+")
RESOURCE_ID_TEXT_PATTERN = re.compile(
    r"\b(?:i|vol|snap|eipalloc|nat|eni|subnet|vpc|sg|ami|rtb|igw|"
    r"eipassoc|acl|lt|fs|fsap|vpce|pcx|tgw|tgw-attach)-[0-9a-f]{8,}\b",
    re.IGNORECASE,
)
IPV4_TEXT_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
)


@dataclass(frozen=True)
class AuditLedgerRedactionPolicy:  # noqa: D101
    enabled: bool = False

    def apply(self, record: dict[str, Any]) -> dict[str, Any]:  # noqa: D102
        if not self.enabled:
            return record
        return self._redact_record(record)

    def _redact_record(self, record: dict[str, Any]) -> dict[str, Any]:
        redacted = dict(record)
        redacted["userIdentity"] = self._redact_user_identity(
            record.get("userIdentity"),
        )
        if redacted.get("recipientAccountId"):
            redacted["recipientAccountId"] = "[redacted-account-id]"
        redacted["requestParameters"] = self._redact_request_context(
            record.get("requestParameters", {}),
        )
        return cast("dict[str, Any]", redact_text_values(redacted))

    def _redact_user_identity(self, value: Any) -> dict[str, Any]:  # noqa: ANN401
        if not isinstance(value, dict):
            return {"type": "Redacted"}
        result: dict[str, Any] = {"type": "Redacted"}
        if value.get("Account"):
            result["Account"] = "[redacted-account-id]"
        if value.get("Arn"):
            result["Arn"] = "[aws-arn]"
        if value.get("UserId"):
            result["UserId"] = "[redacted-user-id]"
        return result

    def _redact_request_context(
        self,
        value: Any,  # noqa: ANN401
        *,
        in_dimensions: bool = False,
    ) -> Any:  # noqa: ANN401
        if isinstance(value, dict):
            redacted: dict[str, Any] = {}
            for key, child in value.items():
                normalized = normalize_request_key(key)
                child_in_dimensions = in_dimensions or normalized == "dimensions"
                if normalized in CONTEXTUAL_REQUEST_KEYS or (child_in_dimensions and normalized == "value"):
                    redacted[key] = redact_contextual_value(child)
                else:
                    redacted[key] = self._redact_request_context(
                        child,
                        in_dimensions=child_in_dimensions,
                    )
            return redacted
        if isinstance(value, list):
            return [self._redact_request_context(item, in_dimensions=in_dimensions) for item in value]
        if isinstance(value, tuple):
            return [self._redact_request_context(item, in_dimensions=in_dimensions) for item in value]
        return value


def redact_request_parameters(value: Any) -> Any:  # noqa: ANN401, D103
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, child in value.items():
            normalized = normalize_request_key(key)
            if any(part in normalized for part in SENSITIVE_REQUEST_KEYS):
                redacted[key] = "[redacted]"
            else:
                redacted[key] = redact_request_parameters(child)
        return redacted
    if isinstance(value, list):
        return [redact_request_parameters(item) for item in value]
    if isinstance(value, tuple):
        return [redact_request_parameters(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    return value


def normalize_request_key(key: Any) -> str:  # noqa: ANN401, D103
    return str(key).lower().replace("_", "").replace("-", "")


def redact_contextual_value(value: Any) -> Any:  # noqa: ANN401, D103
    if isinstance(value, list):
        return ["[redacted]" for _ in value]
    if isinstance(value, tuple):
        return ["[redacted]" for _ in value]
    if isinstance(value, dict):
        return {"_redacted": True}
    if value in (None, ""):
        return value
    return "[redacted]"


def redact_text_values(value: Any) -> Any:  # noqa: ANN401, D103
    if isinstance(value, dict):
        return {key: redact_text_values(child) for key, child in value.items()}
    if isinstance(value, list):
        return [redact_text_values(item) for item in value]
    if isinstance(value, str):
        return redact_sensitive_text(value)
    return value


def redact_sensitive_text(value: str) -> str:  # noqa: D103
    redacted = ACCOUNT_ID_TEXT_PATTERN.sub("[redacted-account-id]", value)
    redacted = ARN_TEXT_PATTERN.sub("[aws-arn]", redacted)
    redacted = RESOURCE_ID_TEXT_PATTERN.sub("[redacted-resource-id]", redacted)
    return IPV4_TEXT_PATTERN.sub("[ip-address]", redacted)
