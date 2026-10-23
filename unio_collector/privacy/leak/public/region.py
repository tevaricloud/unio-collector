"""Declared region metadata and registered-token ARN scan views."""

from __future__ import annotations

import re
from functools import lru_cache

from botocore.loaders import create_loader

from unio_collector.privacy.tokens import TOKEN_RE

ARN_PART_COUNT = 6


@lru_cache(maxsize=1)
def public_regions() -> frozenset[str]:
    """Read finite regional names from the pinned offline SDK endpoint inventory."""
    endpoints = create_loader().load_data("endpoints")
    return frozenset(region for partition in endpoints["partitions"] for region in partition["regions"])


def public_region(value: object) -> bool:
    """Recognize public AWS locations or the fixed strict generalisation marker."""
    return isinstance(value, str) and (value == "aws-region" or value in public_regions())


def registered_arn_view(value: str, generated_tokens: frozenset[str]) -> str:
    """Mask only the public region of a declared, actually generated ARN.

    Account/resource tokens must be registered with this operation. Unregistered
    tokens, raw identifiers, malformed ARNs and arbitrary text stay unchanged.
    Raw-content credential/account/ARN/IP scanning always runs separately.
    """
    parts = value.split(":", 5)
    if len(parts) != ARN_PART_COUNT or parts[0] != "arn" or not _arn_location(parts[1], parts[2], parts[3]):
        return value
    account, resource = parts[4:]
    account_valid = account == "" or (account.startswith("ACCOUNT-") and TOKEN_RE.fullmatch(account) and account in generated_tokens)
    resource_valid = (resource.startswith("RESOURCE-") and TOKEN_RE.fullmatch(resource) and resource in generated_tokens) or (
        parts[2] == "iam" and resource == "root" and account in generated_tokens
    )
    if not account_valid or not resource_valid:
        return value
    parts[3] = ""
    return ":".join(parts)


def public_location(value: object) -> bool:
    """Admit region/AZ literals only inside a declared regional mapping."""
    return public_region(value) or (isinstance(value, str) and len(value) > 1 and value[-1] in "abcdefghijklmnopqrstuvwxyz" and value[:-1] in public_regions())


def _arn_location(partition: str, service: str, region: str) -> bool:
    """Require ARN service syntax and the pinned partition/region association."""
    if re.fullmatch(r"[a-z0-9][a-z0-9-]*", service) is None:
        return False
    return any(name == partition and (region == "aws-region" or region in regions) for name, regions in public_partitions())


@lru_cache(maxsize=1)
def public_partitions() -> tuple[tuple[str, frozenset[str]], ...]:
    """Retain immutable public SDK facts, never ARN values or token authority."""
    endpoints = create_loader().load_data("endpoints")
    return tuple((part["partition"], frozenset(part["regions"])) for part in endpoints["partitions"])
