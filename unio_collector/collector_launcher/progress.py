"""In-place protection status without transcript heartbeats."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from unio_collector.collector_launcher.stage import ProtectionStage

if TYPE_CHECKING:
    from collections.abc import Callable


CANCELLED_EXIT_CODE = 130


class ProtectionProgress:
    """Track actual stages and terminal outcomes with an injectable clock."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        """Start an indeterminate operation; no overall work denominator exists."""
        self._clock = clock
        self._started = clock()
        self._ended: float | None = None
        self.stage = ProtectionStage.PROTECT
        self.state = "running"

    def advance(self, stage: ProtectionStage) -> None:
        """Update only finite stage labels, retaining cancellation requests."""
        if self._ended is None:
            self.stage = stage

    def request_cancel(self) -> None:
        """Keep requested cancellation distinct from a terminal outcome."""
        if self._ended is None:
            self.state = "cancellation requested"

    def finish(self, exit_code: int) -> None:
        """Success is supplied only by the verified protection coordinator."""
        self.state = "completed" if exit_code == 0 else "cancelled" if exit_code == CANCELLED_EXIT_CODE else "failed"
        self._ended = self._clock()

    @property
    def percentage(self) -> int | None:
        """Withhold determinate progress until the complete workflow succeeds."""
        return 100 if self.state == "completed" else None

    def text(self) -> str:
        """Render one status line with elapsed time, excluding evidence values."""
        elapsed = max(0, int((self._ended if self._ended is not None else self._clock()) - self._started))
        label = self.stage.value if self.state == "running" else f"Protection {self.state}"
        return f"{label} â€” elapsed {elapsed // 60}:{elapsed % 60:02d}"


def collection_progress_text(payload: dict[str, object]) -> str:
    """Render existing structured collection progress without changing semantics."""
    event_type = str(payload.get("event_type") or "progress")
    scanner = str(payload.get("scanner_display_name") or payload.get("scanner_id") or "")
    index = payload.get("scanner_index")
    total = payload.get("scanner_total")
    prefix = f"[{index}/{total}] " if index is not None and total is not None else ""
    return f"{prefix}{event_type.replace('_', ' ').title()}: {scanner}".rstrip(": ")
