from __future__ import annotations  # noqa: D100

from datetime import UTC, datetime
from typing import Any


def millis_to_datetime(value: Any) -> datetime | None:  # noqa: ANN401, D103
    if not isinstance(value, (int, float)):
        return None
    return datetime.fromtimestamp(value / 1000, tz=UTC)


def get_log_group_metric_priority(group: dict[str, Any]) -> tuple[int, int, str]:  # noqa: D103
    retention_rank = 0 if "retentionInDays" not in group else 1
    stored_bytes = normalize_stored_bytes(group.get("storedBytes"))
    return (retention_rank, -stored_bytes, str(group.get("logGroupName") or ""))


def normalize_stored_bytes(value: object) -> int:  # noqa: D103
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, float):
        return max(0, int(value))
    return 0
