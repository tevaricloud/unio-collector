from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True)
class AccessAnalyzerFindingRecord:  # noqa: D101
    analyzer_name: str
    analyzer_arn: str
    analyzer_type: str
    region: str
    finding_id: str
    finding_type: str
    status: str
    resource: str | None = None
    resource_type: str | None = None
    principal: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
