from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class BackupRuleRecord:  # noqa: D101
    rule_name: str
    target_backup_vault_name: str | None
    schedule_expression: str | None
    delete_after_days: int | None
    move_to_cold_storage_after_days: int | None
    copy_action_count: int
    copy_destinations: list[str]
    target_vault_exists: bool | None
