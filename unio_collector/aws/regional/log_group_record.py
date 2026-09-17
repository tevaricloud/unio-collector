from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RegionalLogGroupInventoryRecord:  # noqa: D101
    region: str
    log_group: dict[str, Any]

    @property
    def log_group_name(self) -> str:  # noqa: D102
        return str(self.log_group["logGroupName"])
