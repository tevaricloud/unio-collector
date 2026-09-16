from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from collections.abc import Callable

AwsCollectionTaskStatus = Literal[
    "completed",
    "failed",
    "permission_denied",
    "throttled",
    "unsupported_region",
]


@dataclass(frozen=True)
class AwsCollectionTask[T]:  # noqa: D101
    name: str
    scanner_id: str
    collector_id: str
    account_id: str | None
    region: str | None
    service: str
    operation: str
    collect: Callable[[], T]
    payload: dict[str, Any] = field(default_factory=dict)
