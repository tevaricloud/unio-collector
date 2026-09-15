from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.runtime_diagnostics.exception_record import InternalExceptionRecord


@dataclass(frozen=True)
class RunFailureSummary:
    """Internal sanitized run-failure summary artifact."""

    command: str
    phase: str
    exception: InternalExceptionRecord
    elapsed_seconds: float
    diagnostics_paths: dict[str, str] = field(default_factory=dict)
    generated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    contains_client_result_data: bool = False

    def convert_to_dict(self) -> dict[str, Any]:
        """Convert the summary into a JSON-safe object."""
        return {
            "command": self.command,
            "phase": self.phase,
            "exception": self.exception.convert_to_dict(),
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "diagnostics_paths": dict(sorted(self.diagnostics_paths.items())),
            "generated_at": self.generated_at,
            "contains_client_result_data": self.contains_client_result_data,
        }
