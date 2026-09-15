from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ConfigDiagnostic:
    """One non-fatal configuration diagnostic."""

    path: str
    message: str
    severity: str = "warning"
    kind: str = "unknown_key"

    def convert_to_dict(self) -> dict[str, str]:
        """Return a deterministic JSON-ready representation."""
        return {
            "kind": self.kind,
            "message": self.message,
            "path": self.path,
            "severity": self.severity,
        }
