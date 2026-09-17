from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True)
class StoppedInstanceRecord:  # noqa: D101
    instance_id: str
    account_id: str
    region: str
    instance_type: str
    launch_time: datetime | None
    attached_volume_ids: list[str]
    tags: dict[str, str]
