from __future__ import annotations  # noqa: D100

from typing import Protocol


class CacheCancellationToken(Protocol):
    """Minimal cancellation surface accepted by the generic scan cache."""

    reason: str

    def is_cancelled(self) -> bool:
        """Return whether cancellation has been requested."""
        ...
