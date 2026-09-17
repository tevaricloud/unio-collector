from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.backup.selection import BackupSelectionRecord


@dataclass(frozen=True)
class BackupSelectionDetailResult:  # noqa: D101
    record: BackupSelectionRecord
    collection_errors: list[str]
