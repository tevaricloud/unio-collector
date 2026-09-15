from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Literal

ScannerIamRequirementType = Literal["required", "conditional", "optional_enrichment"]
ScannerIamResourceScope = Literal[
    "wildcard_required",
    "resource_scoped_supported",
    "condition_scoped_supported",
    "unknown",
]


@dataclass(frozen=True)
class ScannerIamRequirement:
    """Structured scanner-owned IAM action declaration."""

    api_action: str
    requirement_type: ScannerIamRequirementType
    reason: str
    chargeable: bool
    evidence_categories: tuple[str, ...]
    resource_scope: ScannerIamResourceScope
    resource_scope_reason: str
    conditional_on: str | None = None
