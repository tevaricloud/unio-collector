from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field


@dataclass(frozen=True)
class EcsRegionalCollectionScope:  # noqa: D101
    mode: str
    attempted_regions: list[str]
    collection_regions: list[str]
    skipped_regions: list[str] = field(default_factory=list)
