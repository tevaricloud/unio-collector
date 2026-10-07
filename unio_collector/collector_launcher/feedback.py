"""In-place Tk protection feedback, independent of the transcript."""

from __future__ import annotations

from typing import TYPE_CHECKING

from unio_collector.collector_launcher.progress import ProtectionProgress

if TYPE_CHECKING:
    from collections.abc import Callable
    from tkinter import StringVar, Tk, ttk

    from unio_collector.collector_launcher.protection import ProtectionOperation
    from unio_collector.collector_launcher.stage import ProtectionStage


class ProtectionFeedback:
    """Own actual-stage UI updates and responsive cancellation feedback."""

    def __init__(self, root: Tk, status: StringVar, bar: ttk.Progressbar, append: Callable[[str], None], is_busy: Callable[[], bool]) -> None:
        """Use explicit UI collaborators, never client evidence or secret input."""
        self.root, self.status, self.bar = root, status, bar
        self._append, self._is_busy = append, is_busy
        self._generation: object | None = None
        self.progress: ProtectionProgress

    def start(self, generation: object) -> None:
        """Start indeterminate feedback without recurring transcript output."""
        self._generation = generation
        self.progress = ProtectionProgress()
        self.bar.configure(mode="indeterminate", value=0)
        self.bar.start()
        self._append("Protection started.")
        self.tick(generation)

    def advance(self, stage: ProtectionStage) -> None:
        """Schedule a finite work-stage label from the protection worker."""
        generation = self._generation

        def update() -> None:
            if self._is_busy() and self._generation is generation:
                self.progress.advance(stage)
                self.status.set(self.progress.text())

        self.root.after(0, update)

    def tick(self, generation: object) -> None:
        """Update only the status line; completed generations stop ticking."""
        if self._is_busy() and self._generation is generation:
            self.status.set(self.progress.text())
            self.root.after(1000, lambda: self.tick(generation))

    def finish(self, exit_code: int, generation: object) -> None:
        """Publish the terminal outcome after the coordinator and cleanup."""
        if self._generation is not generation:
            return
        self.progress.finish(exit_code)
        self.bar.stop()
        self.bar.configure(mode="determinate", value=self.progress.percentage or 0)
        self.status.set(self.progress.text())
        self._append(f"Protection {self.progress.state}.")
        self._generation = None

    def cancel(self, operation: ProtectionOperation | None) -> bool:
        """Accept one protection cancellation request without blocking Tk."""
        if self._is_busy() and self._generation is not None and operation is not None and self.progress.state in {"running", "cancellation requested"}:
            if self.progress.state != "cancellation requested":
                operation.cancel()
                self.progress.request_cancel()
                self.status.set(self.progress.text())
                self._append("Protection cancellation requested.")
            return True
        return False
