from __future__ import annotations  # noqa: D100

import traceback
from dataclasses import dataclass
from typing import Any

from unio_collector.aws.cassette.sanitizer import AwsCassetteSanitizer


def sanitize_diagnostic_text(value: object) -> str:
    """Sanitize exception text before it is written or shown."""
    sanitized = AwsCassetteSanitizer().sanitize(str(value))
    return str(sanitized)


@dataclass(frozen=True)
class InternalExceptionRecord:
    """Sanitized internal exception diagnostic record."""

    command: str
    phase: str
    exception_type: str
    sanitized_message: str
    scanner_id: str | None = None
    redacted_traceback: list[str] | None = None

    @classmethod
    def from_exception(
        cls,
        exc: Exception,
        *,
        command: str,
        phase: str,
        scanner_id: str | None = None,
        include_traceback: bool = False,
    ) -> InternalExceptionRecord:
        """Build a safe exception record from an exception instance."""
        redacted_traceback = None
        if include_traceback:
            redacted_traceback = [sanitize_diagnostic_text(line.rstrip("\n")) for line in traceback.format_exception(exc)]
        return cls(
            command=command,
            phase=phase,
            scanner_id=scanner_id,
            exception_type=type(exc).__name__,
            sanitized_message=sanitize_diagnostic_text(exc),
            redacted_traceback=redacted_traceback,
        )

    def convert_to_dict(self) -> dict[str, Any]:
        """Convert the record into a JSON-safe object."""
        payload: dict[str, Any] = {
            "command": self.command,
            "phase": self.phase,
            "exception_type": self.exception_type,
            "sanitized_message": self.sanitized_message,
        }
        if self.scanner_id:
            payload["scanner_id"] = self.scanner_id
        if self.redacted_traceback:
            payload["redacted_traceback"] = self.redacted_traceback
        return payload
