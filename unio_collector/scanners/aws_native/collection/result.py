"""Observed rows and completeness from one read-only provider operation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AwsNativeOperationResult:
    """Carry observed provider rows without recommendation interpretation."""

    items: tuple[dict[str, Any], ...]
    status: str
    code: str = ""
    observed_count: int = 0
    omitted_count: int = 0
    stop_collection: bool = False

    def detail(self, *, region: str, api_action: str) -> dict[str, object]:
        """Return bounded structured operation provenance."""
        return {
            "region": region,
            "api_action": api_action,
            "status": self.status,
            "error_code": self.code,
            "retained_count": len(self.items),
            "observed_count": self.observed_count,
            "omitted_count": self.omitted_count,
            "collection_stopped": self.stop_collection,
        }
