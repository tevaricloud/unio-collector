from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScannerRunnerNoteState:
    """Mutable scanner warning and coverage-note stores."""

    scanner_warnings: dict[str, list[str]] = field(default_factory=dict)
    scanner_coverage_notes: dict[str, list[dict[str, Any]]] = field(
        default_factory=dict,
    )
