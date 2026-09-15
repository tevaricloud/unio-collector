"""Bounded accumulation of numeric metadata without additional provider reads."""

from __future__ import annotations

import json
import math

from unio_collector.aws.analytics.evidence.rows import MAX_NUMERIC_EVIDENCE_BYTES, MAX_NUMERIC_EVIDENCE_ROWS, NumericEvidenceRows


class NumericEvidenceCollector:
    """Retain whole numeric tuples in provider order within explicit budgets."""

    def __init__(self, field_count: int) -> None:
        """Reserve the JSON array delimiters before admitting any rows."""
        self.field_count = field_count
        self.rows: list[tuple[int | float | None, ...]] = []
        self.seen_count = 0
        self.encoded_bytes = 2

    def add(self, *values: object) -> None:
        """Record one whole provider observation or count it as omitted."""
        if len(values) != self.field_count:
            msg = "Numeric evidence observation has the wrong width."
            raise ValueError(msg)
        self.seen_count += 1
        row = tuple(self._number(value) for value in values)
        try:
            encoded_size = len(json.dumps(row, separators=(",", ":"), allow_nan=False).encode("utf-8"))
        except ValueError:
            return
        separator_bytes = int(bool(self.rows))
        if len(self.rows) >= MAX_NUMERIC_EVIDENCE_ROWS or self.encoded_bytes + separator_bytes + encoded_size > MAX_NUMERIC_EVIDENCE_BYTES:
            return
        self.rows.append(row)
        self.encoded_bytes += separator_bytes + encoded_size

    def finish(self, *, read_complete: bool = True) -> NumericEvidenceRows:
        """Freeze the retained rows and account for every omitted observation."""
        return NumericEvidenceRows(
            field_count=self.field_count,
            rows=tuple(self.rows),
            seen_count=self.seen_count,
            omitted_count=self.seen_count - len(self.rows),
            read_complete=read_complete,
        )

    @staticmethod
    def _number(value: object) -> int | float | None:
        if type(value) is int:
            return value
        if type(value) is float and math.isfinite(value):
            return value
        return None
