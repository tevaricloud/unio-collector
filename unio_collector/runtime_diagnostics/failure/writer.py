from __future__ import annotations  # noqa: D100

import json
import time
from typing import TYPE_CHECKING

from unio_collector.runtime_diagnostics.exception_record import InternalExceptionRecord
from unio_collector.runtime_diagnostics.failure.summary import RunFailureSummary

if TYPE_CHECKING:
    from pathlib import Path


class RunFailureSummaryWriter:
    """Write sanitized failure diagnostics to internal telemetry output."""

    def write(
        self,
        *,
        run_dir: Path,
        command: str,
        phase: str,
        exc: Exception,
        started_perf: float,
        include_traceback: bool,
        diagnostics_paths: dict[str, str] | None = None,
    ) -> Path:
        """Write the internal failure summary and return its path."""
        path = run_dir / "telemetry" / "run-failure-summary.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        summary = RunFailureSummary(
            command=command,
            phase=phase,
            exception=InternalExceptionRecord.from_exception(
                exc,
                command=command,
                phase=phase,
                include_traceback=include_traceback,
            ),
            elapsed_seconds=time.perf_counter() - started_perf,
            diagnostics_paths=diagnostics_paths or {},
        )
        write_text_atomically(
            path,
            json.dumps(summary.convert_to_dict(), indent=2, sort_keys=True),
        )
        return path


from unio_collector.core.atomic_artifact import write_text_atomically
