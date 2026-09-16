from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True)
class BackupSelectionRecord:  # noqa: D101
    selection_id: str
    selection_name: str
    iam_role_arn: str | None
    resources: list[str]
    not_resources: list[str]
    conditions: dict[str, Any]
    list_of_tags: list[Any]
    creation_date: datetime | None
