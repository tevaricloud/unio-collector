from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Literal

ProgressEventType = Literal[
    "identity_resolved",
    "scanner_started",
    "scanner_completed",
    "phase_started",
    "phase_status",
    "phase_completed",
]


@dataclass(frozen=True)
class ScanProgressEvent:  # noqa: D101
    event_type: ProgressEventType
    scanner_id: str | None = None
    scanner_display_name: str | None = None
    scanner_index: int | None = None
    scanner_total: int | None = None
    scanner_status: str | None = None
    findings_count: int | None = None
    warning_count: int | None = None
    error_count: int | None = None
    account_id: str | None = None
    message: str | None = None
    phase_id: str | None = None
    phase_display_name: str | None = None
    phase_status: str | None = None
    elapsed_seconds: float | None = None
