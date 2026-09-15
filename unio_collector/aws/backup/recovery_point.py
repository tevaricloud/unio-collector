from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True)
class BackupRecoveryPointRecord:  # noqa: D101
    recovery_point_arn: str
    backup_vault_name: str
    backup_vault_arn: str | None
    account_id: str
    region: str
    resource_arn: str | None
    resource_type: str | None
    resource_name: str | None
    status: str | None
    backup_size_bytes: int | None
    creation_date: datetime | None
    completion_date: datetime | None
    calculated_delete_at: datetime | None
    calculated_retention_days: int | None
    age_days: int | None
