from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class AccessAnalyzerRecord:  # noqa: D101
    analyzer_name: str
    analyzer_arn: str
    analyzer_type: str
    region: str
    status: str | None = None
