from __future__ import annotations  # noqa: D100

import json
from typing import TYPE_CHECKING, Any

from unio_collector.runtime_diagnostics.event import (
    RuntimeDiagnosticsEvent,
)

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.scan_workflow.progress import ScanProgressEvent


class RuntimeDiagnosticsRecorder:
    """Append safe operational runtime events to a JSONL telemetry artifact."""

    def __init__(self, *, enabled: bool = False) -> None:  # noqa: D107
        self.enabled = enabled
        self._path: Path | None = None
        self._buffer: list[RuntimeDiagnosticsEvent] = []
        self._history: list[RuntimeDiagnosticsEvent] = []
        self._active_artifacts_by_phase: dict[str, str] = {}

    @property
    def path(self) -> Path | None:  # noqa: D102
        return self._path

    def attach_path(self, path: Path) -> None:  # noqa: D102
        if not self.enabled:
            return
        self._path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        for event in self._buffer:
            self._append_event(event)
        self._buffer.clear()

    def record_event(  # noqa: D102
        self,
        *,
        phase: str,
        event: str,
        status: str | None = None,
        duration_seconds: float | None = None,
        scanner_id: str | None = None,
        scanner_display_name: str | None = None,
        artifact_path: str | None = None,
        message: str | None = None,
    ) -> None:
        if not self.enabled:
            return
        self._update_active_artifact(
            phase=phase,
            event=event,
            artifact_path=artifact_path,
        )
        self.record(
            RuntimeDiagnosticsEvent.create(
                phase=phase,
                event=event,
                status=status,
                duration_seconds=duration_seconds,
                scanner_id=scanner_id,
                scanner_display_name=scanner_display_name,
                artifact_path=artifact_path,
                message=message,
            ),
        )

    def record_progress_event(self, event: ScanProgressEvent) -> None:  # noqa: D102
        if not self.enabled:
            return
        if event.event_type.startswith("scanner_"):
            self.record_event(
                phase="scanner_execution",
                event=event.event_type,
                status=event.scanner_status,
                duration_seconds=event.elapsed_seconds,
                scanner_id=event.scanner_id,
                scanner_display_name=event.scanner_display_name,
                message=self._safe_message(event.message),
            )
            return
        if event.event_type.startswith("phase_"):
            self.record_event(
                phase=event.phase_id or "unknown",
                event=event.event_type,
                status=event.phase_status,
                duration_seconds=event.elapsed_seconds,
            )
            return
        self.record_event(
            phase="scan_execution",
            event=event.event_type,
            status=event.phase_status or event.scanner_status,
        )

    def record_watchdog_event(  # noqa: D102
        self,
        *,
        phase_id: str,
        severity: str,
        elapsed_seconds: float,
    ) -> None:
        self.record_event(
            phase=phase_id,
            event="watchdog_warning",
            status=severity,
            duration_seconds=elapsed_seconds,
            message=(f"Phase runtime exceeded the configured diagnostics watchdog {severity} threshold."),
        )

    def record(self, event: RuntimeDiagnosticsEvent) -> None:  # noqa: D102
        if not self.enabled:
            return
        self._history.append(event)
        if self._path is None:
            self._buffer.append(event)
            return
        self._append_event(event)

    def convert_events_to_dicts(self) -> list[dict[str, Any]]:  # noqa: D102
        return [event.convert_to_dict() for event in self._history]

    def get_active_artifact(self, phase: str | None = None) -> str | None:  # noqa: D102
        if phase:
            return self._active_artifacts_by_phase.get(phase)
        if not self._active_artifacts_by_phase:
            return None
        return next(reversed(self._active_artifacts_by_phase.values()))

    def _append_event(self, _event: RuntimeDiagnosticsEvent) -> None:
        if self._path is None:
            return
        write_text_atomically(
            self._path,
            "".join(json.dumps(item.convert_to_dict(), sort_keys=True) + "\n" for item in self._history),
        )

    def _update_active_artifact(
        self,
        *,
        phase: str,
        event: str,
        artifact_path: str | None,
    ) -> None:
        if not artifact_path:
            return
        if event.endswith("_started"):
            self._active_artifacts_by_phase[phase] = artifact_path
            return
        if event.endswith(("_completed", "_failed")) and self._active_artifacts_by_phase.get(phase) == artifact_path:
            self._active_artifacts_by_phase.pop(phase, None)

    def _safe_message(self, message: Any) -> str | None:  # noqa: ANN401
        if message in (None, ""):
            return None
        text = str(message)
        if len(text) > 240:  # noqa: PLR2004
            return text[:237] + "..."
        return text


from unio_collector.core.atomic_artifact import write_text_atomically
