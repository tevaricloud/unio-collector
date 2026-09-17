from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityWarning:
    """Structured non-secret warning emitted by privacy workflows."""

    code: str
    category: str
    artifact: str
    message: str

    def convert_to_dict(self) -> dict[str, str]:
        """Return a stable JSON-safe warning payload."""
        return {
            "code": self.code,
            "category": self.category,
            "artifact": self.artifact,
            "message": self.message,
        }


def warning_messages(warnings: tuple[SecurityWarning, ...]) -> tuple[str, ...]:
    """Return compatibility messages for structured warnings."""
    return tuple(warning.message for warning in warnings)
