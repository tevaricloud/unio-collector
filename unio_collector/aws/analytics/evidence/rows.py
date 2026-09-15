"""Whole numeric rows with explicit retained and omitted evidence counts."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass

MAX_NUMERIC_EVIDENCE_ROWS = 2048
MAX_NUMERIC_EVIDENCE_BYTES = 65536


@dataclass(frozen=True)
class NumericEvidenceRows:
    """Retain bounded provider numbers without interpreting their magnitude."""

    field_count: int
    rows: tuple[tuple[int | float | None, ...], ...] = ()
    seen_count: int = 0
    omitted_count: int = 0
    read_complete: bool = True

    def __post_init__(self) -> None:
        """Reject malformed row shapes, non-finite values and inconsistent counts."""
        if type(self.field_count) is not int or self.field_count < 1:
            msg = "Numeric evidence field count is invalid."
            raise ValueError(msg)
        if type(self.seen_count) is not int or type(self.omitted_count) is not int or self.omitted_count < 0:
            msg = "Numeric evidence counts are invalid."
            raise ValueError(msg)
        if self.seen_count != len(self.rows) + self.omitted_count or type(self.read_complete) is not bool:
            msg = "Numeric evidence completeness is inconsistent."
            raise ValueError(msg)
        if not isinstance(self.rows, tuple) or len(self.rows) > MAX_NUMERIC_EVIDENCE_ROWS:
            msg = "Numeric evidence exceeds its whole-row limit."
            raise ValueError(msg)
        for row in self.rows:
            if not isinstance(row, tuple) or len(row) != self.field_count:
                msg = "Numeric evidence row shape is invalid."
                raise ValueError(msg)
            if any(value is not None and (type(value) not in {int, float} or (isinstance(value, float) and not math.isfinite(value))) for value in row):
                msg = "Numeric evidence contains an invalid provider value."
                raise ValueError(msg)
        if len(json.dumps(self.rows, separators=(",", ":"), allow_nan=False).encode("utf-8")) > MAX_NUMERIC_EVIDENCE_BYTES:
            msg = "Numeric evidence exceeds its encoded-byte limit."
            raise ValueError(msg)
