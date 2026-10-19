"""Deterministic framework collection instant for synthetic edge correlation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from datetime import tzinfo


class SyntheticEdgeClock(datetime):
    """Supply a clock input to the actual producer instead of rewriting its output."""

    @classmethod
    def now(cls, tz: tzinfo | None = None) -> Self:
        """Keep the production UTC clock contract deterministic for private/public proof."""
        if tz is not UTC:
            message = "Unexpected synthetic edge clock timezone"
            raise AssertionError(message)
        return cls(2026, 1, 31, 12, tzinfo=UTC)
