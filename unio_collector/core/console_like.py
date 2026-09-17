from __future__ import annotations  # noqa: D100

from typing import Protocol


class ConsoleLike(Protocol):
    """Minimal console interface for application services that print progress."""

    def print(self, *values: object, **kwargs: object) -> None: ...  # noqa: D102
