from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.evidence.permission.planning.requirement_type import RequirementType


@dataclass(frozen=True)
class ScannerPermissionProvenance:
    """Per-scanner explanation for a merged IAM action requirement."""

    scanner_id: str
    reason: str
    requirement_type: RequirementType
    chargeable: bool
    conditional_on: str | None = None
    evidence_categories: tuple[str, ...] = ()
    authorization_scope_variant_ids: tuple[str, ...] = ()
