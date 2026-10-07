"""Local launcher worker execution and cleanup outcome handling."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.collector_launcher.result import CommandResult


class LauncherTask:
    """Complete worker cleanup before notifying the UI of its outcome."""

    def __init__(
        self,
        task: Callable[[], CommandResult],
        append: Callable[[str], None],
        finished: Callable[[int], object],
        *,
        cleanup: object | None = None,
        streamed: bool = False,
        report_exit: bool = True,
    ) -> None:
        """Keep UI scheduling in the caller and work on the background thread."""
        self.task, self._append, self._finished = task, append, finished
        self.cleanup, self.streamed, self.report_exit = cleanup, streamed, report_exit

    def __call__(self) -> None:
        """Execute the command and preserve failed cleanup as a failed outcome."""
        exit_code = 1
        try:
            result = self.task()
            if result.output and not self.streamed:
                self._append(result.output)
            exit_code = result.exit_code
            if self.report_exit:
                self._append(f"Command completed with exit code {result.exit_code}.")
        except Exception as exc:  # noqa: BLE001
            self._append(f"Operation failed: {exc}")
        finally:
            try:
                if callable(self.cleanup):
                    self.cleanup()
            except Exception:  # noqa: BLE001
                exit_code = 1
                self._append("Operation cleanup failed.")
            finally:
                self._finished(exit_code)
