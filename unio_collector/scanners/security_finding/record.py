from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True)
class SecurityFindingRecord:  # noqa: D101
    provider: str
    finding_id: str
    region: str
    title: str
    severity: str | int | float | None
    resource_type: str | None = None
    resource_id: str | None = None
    description: str | None = None
    finding_type: str | None = None
    workflow_status: str | None = None
    record_state: str | None = None
    updated_at: datetime | None = None
