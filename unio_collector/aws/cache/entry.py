from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from threading import Event
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.cache.failure import CacheFailureSnapshot


@dataclass
class CacheEntry[T]:  # noqa: D101
    generation: int
    owner_id: str
    event: Event = field(default_factory=Event)
    value: T | None = None
    failure: CacheFailureSnapshot | None = None
    loaded: bool = False
    abandoned: bool = False
