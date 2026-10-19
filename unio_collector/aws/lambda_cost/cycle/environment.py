"""Existing coarse Lambda environment/bucket string-match semantics."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping


def environment_mentions_bucket(variables: Mapping[str, str], bucket_names: Iterable[str]) -> bool:
    """Preserve the historical case-insensitive heuristic, not a confirmed cyclic trigger."""
    values = " ".join(variables.values()).lower()
    return bool(values) and any(bucket.lower() in values for bucket in bucket_names)
