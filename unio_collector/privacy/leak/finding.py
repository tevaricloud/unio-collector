from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class LeakFinding:
    """One protected archive leak finding."""

    path: str
    category: str

    def convert_to_dict(self) -> dict[str, str]:
        """Return JSON-safe finding data."""
        return {"path": self.path, "category": self.category}
