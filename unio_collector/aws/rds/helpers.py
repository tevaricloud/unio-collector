from __future__ import annotations  # noqa: D100

from datetime import UTC, datetime
from typing import Any


def age_in_days(value: Any, now: datetime) -> int | None:  # noqa: ANN401, D103
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return max((now - value).days, 0)


def get_optional_string(data: dict[str, Any], key: str) -> str | None:  # noqa: D103
    value = data.get(key)
    if value is None:
        return None
    return str(value)


def get_optional_int(data: dict[str, Any], key: str) -> int | None:  # noqa: D103
    value = data.get(key)
    if isinstance(value, int):
        return value
    return None


def tags_to_dict(tags: list[dict[str, Any]]) -> dict[str, str]:  # noqa: D103
    return {str(tag.get("Key")): str(tag.get("Value")) for tag in tags if tag.get("Key")}
