from __future__ import annotations  # noqa: D100

from dataclasses import asdict, dataclass
from typing import Any, Literal

PermissionCategory = Literal["read_only", "write_limited", "admin_like", "unknown"]


@dataclass(frozen=True)
class PermissionSummary:
    """Run-level permission observation summary prepared before reporting."""

    generated_at: str
    profile_name: str | None
    mode: str
    category: PermissionCategory
    assessment_method: str
    caller_identity: dict[str, Any]
    account_id: str
    available_actions: list[str]
    missing_actions: list[str]
    service_unavailable_actions: list[str]
    not_attempted_actions: list[str]
    not_attempted_conditional_actions: list[str]
    unknown_actions: list[str]
    write_actions_observed: list[str]
    scanner_permissions: list[Any]
    permission_failures: list[dict[str, Any]]
    limitations: list[str]

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        return asdict(self)
