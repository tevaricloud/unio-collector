from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True)
class IamAccessKeyRecord:  # noqa: D101
    access_key_id: str
    status: str
    created_at: datetime | None
    last_used_at: datetime | None = None
    last_used_service: str | None = None
    last_used_region: str | None = None
    last_used_available: bool = True
