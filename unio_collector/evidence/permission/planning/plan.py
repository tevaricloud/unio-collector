from __future__ import annotations  # noqa: D100

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.evidence.permission.planning.requirement import (
        PermissionRequirement,
    )


@dataclass(frozen=True)
class PermissionPlan:
    """Complete collector-safe permission plan."""

    schema_version: str
    provider_id: str
    selected_scanner_ids: tuple[str, ...]
    requirements: tuple[PermissionRequirement, ...]
    excluded_chargeable_requirements: tuple[PermissionRequirement, ...]
    read_only_actions: tuple[str, ...]
    rejected_actions: tuple[str, ...]
    wildcard_justifications: tuple[dict[str, str], ...]
    warnings: tuple[dict[str, str], ...]
    limitations: tuple[str, ...]
    aws_scope: dict[str, object] | None = None
    policy_status: str = "unresolved_policy_plan"
    deployable: bool = False
    unresolved_actions: tuple[str, ...] = ()
    authorization_catalogue_version: str | None = None
    credential_delegation_actions: tuple[str, ...] = ()

    @property
    def valid(self) -> bool:
        """Return whether the plan contains only accepted runtime-safe actions."""
        return not self.rejected_actions

    def convert_to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible payload."""
        payload = asdict(self)
        payload["requirements"] = [item.convert_to_dict() for item in self.requirements]
        payload["excluded_chargeable_requirements"] = [item.convert_to_dict() for item in self.excluded_chargeable_requirements]
        return payload
