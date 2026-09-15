from __future__ import annotations  # noqa: D100

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

CANONICALIZATION_VERSION = "2026-03"


@dataclass(frozen=True)
class CanonicalValue:
    """Versioned canonical value used as token input."""

    category: str
    value: str
    version: str = CANONICALIZATION_VERSION


ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
EMAIL_RE = re.compile(r"^([^@\s]+)@([^@\s]+\.[^@\s]+)$")


def canonicalize_value(category: str, value: object) -> CanonicalValue:  # noqa: C901
    """Return a deterministic canonical representation for a privacy category."""
    text = str(value).strip()
    normalized_category = category.lower().replace("-", "_")
    if normalized_category == "aws_account_id":
        return CanonicalValue(category=normalized_category, value=text)
    if normalized_category == "arn":
        return CanonicalValue(category=normalized_category, value=text)
    if normalized_category in {"resource_id", "resource_name", "bucket_name", "tag_key", "tag_value", "iam_role", "free_text"}:
        return CanonicalValue(category=normalized_category, value=text)
    if normalized_category == "email":
        match = EMAIL_RE.fullmatch(text)
        if not match:
            return CanonicalValue(category=normalized_category, value=text)
        return CanonicalValue(
            category=normalized_category,
            value=f"{match.group(1)}@{match.group(2).lower()}",
        )
    if normalized_category in {"dns_name", "hostname"}:
        return CanonicalValue(
            category="dns_name",
            value=text.rstrip(".").lower(),
        )
    if normalized_category in {"ipv4", "ipv6"}:
        return CanonicalValue(
            category=normalized_category,
            value=str(ipaddress.ip_address(text)),
        )
    if normalized_category == "cidr":
        return CanonicalValue(
            category=normalized_category,
            value=str(ipaddress.ip_network(text, strict=False)),
        )
    if normalized_category == "url":
        parsed = urlsplit(text)
        host = parsed.hostname.lower() if parsed.hostname else ""
        netloc = host
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        return CanonicalValue(
            category=normalized_category,
            value=urlunsplit(
                (
                    parsed.scheme.lower(),
                    netloc,
                    parsed.path,
                    parsed.query,
                    "",
                ),
            ),
        )
    return CanonicalValue(category=normalized_category, value=text)
