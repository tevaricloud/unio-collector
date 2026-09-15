from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True)
class SnapshotRecord:  # noqa: D101
    snapshot_id: str
    account_id: str
    region: str
    volume_id: str | None
    volume_size_gib: int | None
    start_time: datetime | None
    age_days: int
    description: str | None
    tags: dict[str, str]
