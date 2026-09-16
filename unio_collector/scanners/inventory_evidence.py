from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class InventoryEvidence:
    """Normalized scanner evidence for regional inventory collectors."""

    records: list[Any] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create_empty(cls) -> InventoryEvidence:  # noqa: D102
        return cls()
