"""Commitment applicability and capacity specification contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class CommitmentSpecification:
    """Describe the applicability and purchased capacity of a commitment."""

    scope: str | None = None
    region: str | None = None
    availability_zone: str | None = None
    instance_family: str | None = None
    instance_type: str | None = None
    commitment_class: str | None = None
    platform: str | None = None
    tenancy: str | None = None
    quantity: Decimal | None = None
    capacity_unit: str | None = None
    lifecycle_state: str | None = None
