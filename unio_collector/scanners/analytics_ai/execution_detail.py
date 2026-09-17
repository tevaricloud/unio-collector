from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class AnalyticsAiExecutionDetailSpec:  # noqa: D101
    service_label: str
    resource_label: str
    resource_count_fields: tuple[str, ...]
    detail_count_fields: tuple[str, ...]
