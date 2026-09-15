from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class SharedEvidencePrefetchFailure:
    """Failure record for a shared evidence prefetch task."""

    task_name: str
    error_code: str
    error_message: str
    duration_ms: int

    def convert_to_dict(self) -> dict[str, object]:
        """Return a safe summary record for scheduler diagnostics."""
        return {
            "namespace": self.task_name,
            "status": "failed",
            "error_code": self.error_code,
            "error_message": self.error_message,
            "duration_ms": self.duration_ms,
            "contains_client_result_data": False,
        }
