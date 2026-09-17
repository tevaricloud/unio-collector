from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScannerPermissionSummary:
    """Permission observation summary for one scanner."""

    scanner_id: str
    required_permission_level: str
    required_iam_actions: list[str]
    conditional_iam_actions: list[str] = field(default_factory=list)
    available_actions: list[str] = field(default_factory=list)
    available_conditional_actions: list[str] = field(default_factory=list)
    missing_actions: list[str] = field(default_factory=list)
    missing_conditional_actions: list[str] = field(default_factory=list)
    service_unavailable_actions: list[str] = field(default_factory=list)
    service_unavailable_conditional_actions: list[str] = field(default_factory=list)
    not_attempted_actions: list[str] = field(default_factory=list)
    not_attempted_conditional_actions: list[str] = field(default_factory=list)
    unknown_actions: list[str] = field(default_factory=list)
    unknown_conditional_actions: list[str] = field(default_factory=list)
    scanner_status: str = "unknown"
