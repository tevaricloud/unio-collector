from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DynamoDbTableTagResult:  # noqa: D101
    table_name: str
    tags: dict[str, str] = field(default_factory=dict)
    permission_errors: list[str] = field(default_factory=list)
