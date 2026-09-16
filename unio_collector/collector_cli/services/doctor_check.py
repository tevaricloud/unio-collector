from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class CollectorDoctorCheck:
    """One collector doctor preflight check."""

    name: str
    status: str
    message: str

    def convert_to_dict(self) -> dict[str, str]:
        """Return a deterministic dictionary."""
        return {
            "message": self.message,
            "name": self.name,
            "status": self.status,
        }


__all__ = ["CollectorDoctorCheck"]
