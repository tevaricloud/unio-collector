from __future__ import annotations  # noqa: D100

import re
from typing import Any, ClassVar


class AwsCassetteSanitizer:
    """Sanitize common AWS identifiers before writing development cassettes."""

    ACCOUNT_ID_RE = re.compile(r"\b\d{12}\b")
    ARN_RE = re.compile(r"arn:aws[a-z-]*:[^\s,)\]]+", re.IGNORECASE)
    ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
    PRINCIPAL_ID_RE = re.compile(r"\b(?:AIDA|AROA)[A-Z0-9]{16,32}\b")
    RESOURCE_ID_RE = re.compile(
        r"\b(?:acl|ami|eipalloc|eni|fs|igw|i|nat|pcx|rtb|sg|snap|subnet|"
        r"tgw|vol|vpc|vpce)-[0-9a-f]{3,32}\b",
        re.IGNORECASE,
    )
    IPV4_RE = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    )
    REGION_RE = re.compile(
        r"\b(?:af|ap|ca|eu|il|me|mx|sa|us)-(?:central|north|south|east|west|"
        r"northeast|southeast|southwest|northwest)-\d\b",
        re.IGNORECASE,
    )
    DOMAIN_RE = re.compile(
        r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"(?:com|net|org|co|io|dev|cloud|internal|local|corp)\b",
    )
    LOCAL_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\[^\s\"']+|/(?:Users|home)/[^\s\"']+")
    CONSOLE_URL_RE = re.compile(
        r"https://[^\s\"'<>)]*console\.aws\.amazon\.com[^\s\"'<>)]*",
        re.IGNORECASE,
    )
    REQUEST_ID_KEYS: ClassVar[set[str]] = {
        "RequestId",
        "RequestID",
        "x-amzn-requestid",
    }
    SENSITIVE_KEY_RE = re.compile(
        r"(secret|token|credential|password|access_key|session)",
        re.IGNORECASE,
    )

    def sanitize(self, value: Any) -> Any:  # noqa: ANN401, D102
        if isinstance(value, dict):
            return {str(key): self._sanitize_key_value(str(key), nested_value) for key, nested_value in value.items()}
        if isinstance(value, list):
            return [self.sanitize(item) for item in value]
        if isinstance(value, tuple):
            return [self.sanitize(item) for item in value]
        if isinstance(value, str):
            return self._sanitize_text(value)
        return value

    def _sanitize_key_value(self, key: str, value: Any) -> Any:  # noqa: ANN401
        key_lower = key.lower()
        if key in self.REQUEST_ID_KEYS:
            return "[redacted-request-id]"
        if key_lower in {"arn", "resource_arn", "function_arn"}:
            return "[redacted-arn]"
        if key_lower == "userid":
            return "[aws-principal-id]"
        if self.SENSITIVE_KEY_RE.search(key):
            return "[redacted]"
        return self.sanitize(value)

    def _sanitize_text(self, value: str) -> str:
        redacted = self.CONSOLE_URL_RE.sub("Console link redacted", value)
        redacted = self.LOCAL_PATH_RE.sub("[local-path]", redacted)
        redacted = self.DOMAIN_RE.sub("[redacted-domain]", redacted)
        redacted = self.REGION_RE.sub("[redacted-region]", redacted)
        redacted = self.IPV4_RE.sub("[ip-address]", redacted)
        redacted = self.ACCESS_KEY_RE.sub("[aws-access-key]", redacted)
        redacted = self.PRINCIPAL_ID_RE.sub("[aws-principal-id]", redacted)
        redacted = self.ARN_RE.sub("[redacted-arn]", redacted)
        redacted = self.ACCOUNT_ID_RE.sub("[redacted-account-id]", redacted)
        return self.RESOURCE_ID_RE.sub("[redacted-resource-id]", redacted)
