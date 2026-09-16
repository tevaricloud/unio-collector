from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class BillingRegionCoveragePayload:
    """Structured billing-region coverage evidence payload."""

    payload: dict[str, Any]

    def convert_to_dict(self) -> dict[str, Any]:
        """Return a plain dictionary copy of the coverage payload."""
        return dict(self.payload)
