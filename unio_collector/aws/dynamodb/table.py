from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DynamoDbTableDetail:  # noqa: D101
    table_name: str
    table: dict[str, Any] | None = None
    pitr_enabled: bool = False
    ttl_enabled: bool = False
    tags: dict[str, str] = field(default_factory=dict)
    permission_errors: list[str] = field(default_factory=list)
