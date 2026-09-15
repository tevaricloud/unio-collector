"""Normalized CloudTrail selector evidence for deterministic analysis."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CloudTrailSelectorEvidence:
    """Allowlisted provider facts from a basic or advanced event selector."""

    trail_name: str = ""
    selector_kind: str = ""
    selector_name: str | None = None
    read_write_type: str | None = None
    include_management_events: bool | None = None
    exclude_management_event_sources: list[str] = field(default_factory=list)
    resource_types: list[str] = field(default_factory=list)
    resource_values: list[str] = field(default_factory=list)
    event_categories: list[str] = field(default_factory=list)
    field_conditions: list[dict[str, object]] = field(default_factory=list)


__all__ = ["CloudTrailSelectorEvidence"]
