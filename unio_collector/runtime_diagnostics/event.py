from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class RuntimeDiagnosticsEvent:  # noqa: D101
    phase: str
    event: str
    timestamp: str
    status: str | None = None
    duration_seconds: float | None = None
    scanner_id: str | None = None
    scanner_display_name: str | None = None
    artifact_path: str | None = None
    message: str | None = None

    @classmethod
    def create(  # noqa: D102
        cls,
        *,
        phase: str,
        event: str,
        status: str | None = None,
        duration_seconds: float | None = None,
        scanner_id: str | None = None,
        scanner_display_name: str | None = None,
        artifact_path: str | None = None,
        message: str | None = None,
    ) -> RuntimeDiagnosticsEvent:
        return cls(
            phase=phase,
            event=event,
            timestamp=datetime.now(UTC).isoformat(),
            status=status,
            duration_seconds=duration_seconds,
            scanner_id=scanner_id,
            scanner_display_name=scanner_display_name,
            artifact_path=artifact_path,
            message=message,
        )

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        payload: dict[str, Any] = {
            "timestamp": self.timestamp,
            "phase": self.phase,
            "event": self.event,
        }
        optional_values = {
            "status": self.status,
            "duration_seconds": self.duration_seconds,
            "scanner_id": self.scanner_id,
            "scanner_display_name": self.scanner_display_name,
            "artifact_path": self.artifact_path,
            "message": self.message,
        }
        payload.update(
            {key: value for key, value in optional_values.items() if value not in (None, "")},
        )
        return payload
