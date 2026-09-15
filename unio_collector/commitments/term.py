"""Commitment term and remaining-duration contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True)
class CommitmentTerm:
    """Carry observed commitment dates and derived duration metadata."""

    start: datetime | None = None
    end: datetime | None = None
    term_seconds: int | None = None
    term_label: str | None = None
    remaining_seconds: int | None = None
