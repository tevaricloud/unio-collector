from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AwsPageCollectionResult:  # noqa: D101
    pages: list[dict[str, Any]]
    page_count: int
    resources_returned: int
