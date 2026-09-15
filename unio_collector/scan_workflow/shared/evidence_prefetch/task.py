from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass(frozen=True)
class SharedEvidencePrefetchTask:
    """A bounded pre-scan evidence task that is safe to run independently."""

    name: str
    run: Callable[[], None]
