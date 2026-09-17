from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True)
class EbsVolumeRecord:  # noqa: D101
    volume_id: str
    account_id: str
    region: str
    size_gib: int
    volume_type: str
    state: str
    create_time: datetime | None
    encrypted: bool | None
    tags: dict[str, str]
