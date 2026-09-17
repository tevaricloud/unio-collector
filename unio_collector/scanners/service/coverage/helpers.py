from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.service.coverage.record import ServiceCoverageRecord


def count_records(records: list[ServiceCoverageRecord], resource_type: str) -> int:  # noqa: D103
    return sum(1 for record in records if record.resource_type == resource_type)


def stable_id(value: str) -> str:  # noqa: D103
    sanitized = "".join(character.lower() if character.isalnum() else "-" for character in value).strip("-")
    while "--" in sanitized:
        sanitized = sanitized.replace("--", "-")
    return sanitized[-80:] or "unknown"
