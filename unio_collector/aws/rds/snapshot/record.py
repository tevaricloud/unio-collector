from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True)
class RdsSnapshotRecord:  # noqa: D101
    snapshot_identifier: str
    snapshot_arn: str | None
    source_identifier: str | None
    account_id: str
    region: str
    snapshot_kind: str
    snapshot_type: str
    engine: str | None
    status: str | None
    storage_gib: int | None
    created_at: datetime | None
    age_days: int
    tags: dict[str, str]
