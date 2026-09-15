from __future__ import annotations  # noqa: D100

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

CurS3ObjectFetcher = Callable[[str, str], bytes]


@dataclass(frozen=True)
class CurDataSource:  # noqa: D101
    source_type: str
    display_name: str
    local_path: Path | None = None
    bucket: str | None = None
    key: str | None = None

    @property
    def name(self) -> str:  # noqa: D102
        if self.local_path is not None:
            return str(self.local_path)
        return self.display_name
