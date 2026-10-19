"""Stateful accounting for existing region and timestamp generalisation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from unio_collector.privacy.patterns import TIMESTAMP_RE

if TYPE_CHECKING:
    from unio_collector.privacy.registry import ClassificationSummary


class PrivacyValueGeneraliser:
    """Keep value generalisation separate from recursive bundle traversal."""

    def __init__(self, summary: ClassificationSummary) -> None:
        """Share the caller's classification accounting."""
        self.summary = summary

    def generalise(self, value: str, category: str | None) -> str:
        """Apply the existing category generalisation and retain its counters."""
        if category == "region":
            self.summary.regions_generalised += 1
            self.summary.preserved += 1
            return "aws-region"
        if category == "timestamp":
            if TIMESTAMP_RE.match(value):
                self.summary.timestamps_generalised += 1
                self.summary.preserved += 1
                return value[:7]
            self.summary.unclassified.append("timestamp")
            return value
        self.summary.preserved += 1
        return value
