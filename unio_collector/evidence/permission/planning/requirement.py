from __future__ import annotations  # noqa: D100

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from unio_collector.evidence.permission.planning.provenance import (
        ScannerPermissionProvenance,
    )
    from unio_collector.evidence.permission.planning.requirement_type import RequirementType

ResourceScope = Literal[
    "wildcard_required",
    "resource_scoped_supported",
    "condition_scoped_supported",
    "unknown",
]


@dataclass(frozen=True)
class PermissionRequirement:
    """One collector-safe permission requirement derived from metadata."""

    requirement_id: str
    provider_id: str
    service: str
    api_action: str
    requirement_type: RequirementType
    chargeable: bool
    resource_scope: ResourceScope
    scanner_ids: tuple[str, ...]
    scanner_provenance: tuple[ScannerPermissionProvenance, ...]
    evidence_categories: tuple[str, ...]
    conditional_on: str | None = None
    retryable: bool = False
    expected_error_codes: tuple[str, ...] = ()
    client_explanation: str = ""
    diagnostic_context: str = ""
    review_notes: str = ""
    wildcard_justification: str = ""
    authorization_scope_variant_ids: tuple[str, ...] = ()
    resource_arn_templates: tuple[str, ...] = ()
    resolved_resources: tuple[str, ...] = ()
    iam_conditions: tuple[dict[str, object], ...] = ()
    unresolved_variables: tuple[str, ...] = ()
    authorization_references: tuple[str, ...] = ()
    scope_status: str = "unresolved"

    def convert_to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible payload."""
        return asdict(self)
