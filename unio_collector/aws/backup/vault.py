from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class BackupVaultRecord:  # noqa: D101
    backup_vault_name: str
    backup_vault_arn: str | None
    account_id: str
    region: str
    recovery_point_count: int | None
    encryption_key_arn: str | None
    tags: dict[str, str]
    collection_errors: list[str]
    tags_collected: bool = True
