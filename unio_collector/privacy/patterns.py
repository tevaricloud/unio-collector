from __future__ import annotations  # noqa: D100

import re

ACCOUNT_RE = re.compile(r"(?<![\d.])\d{12}(?![\d.])")
ARN_RE = re.compile(r"\barn:aws(?:-[a-z]+)?:[^\s,\"'<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}(?:-\d{2})?(?:[T\s].*)?$")
DNS_RE = re.compile(
    r"\b(?=.{4,253}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.IGNORECASE,
)
RESOURCE_RE = re.compile(
    r"\b(?:i|vol|snap|sg|subnet|vpc|nat|eni|lt|ami|igw|rtb|acl|vpce)-[0-9a-f]{8,32}\b",
    re.IGNORECASE,
)

ARN_PART_COUNT = 6
IPV4_VERSION = 4
