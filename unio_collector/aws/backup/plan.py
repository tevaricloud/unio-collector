from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from unio_collector.aws.backup.rule import BackupRuleRecord
    from unio_collector.aws.backup.selection import BackupSelectionRecord


@dataclass(frozen=True)
class BackupPlanRecord:  # noqa: D101
    backup_plan_id: str
    backup_plan_arn: str | None
    backup_plan_name: str
    account_id: str
    region: str
    rules: list[BackupRuleRecord]
    selections: list[BackupSelectionRecord]
    tags: dict[str, str]
    creation_date: datetime | None
    last_execution_date: datetime | None
    collection_errors: list[str]
    tags_collected: bool = True
