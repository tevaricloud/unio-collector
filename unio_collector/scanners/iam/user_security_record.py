from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from unio_collector.scanners.iam.access_key_record import IamAccessKeyRecord


@dataclass(frozen=True)
class IamUserSecurityRecord:  # noqa: D101
    user_name: str
    user_id: str | None = None
    arn: str | None = None
    has_console_profile: bool | None = False
    login_profile_created_at: datetime | None = None
    password_last_used_at: datetime | None = None
    mfa_device_count: int | None = 0
    access_keys: tuple[IamAccessKeyRecord, ...] = ()
