"""Provider quota names and numeric response parsing."""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Any


def normalize_quota_text(value: str) -> str:  # noqa: D103
    text = value.casefold()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def parse_quota_value(value: Any) -> Decimal | None:  # noqa: ANN401, D103
    if value in (None, ""):
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def parse_finite_quota_value(value: object) -> Decimal | None:
    """Missing or non-finite provider values remain unavailable evidence."""
    parsed = parse_quota_value(value)
    return parsed if parsed is not None and parsed.is_finite() and parsed >= 0 else None


def quota_response_records(response: object, result_key: str) -> list[dict[str, Any]]:
    """Reject malformed lists instead of counting missing records as zero usage."""
    values = response.get(result_key) if isinstance(response, dict) else None
    if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
        message = "Quota collection response is missing a complete result list."
        raise ValueError(message)
    return list(values)
