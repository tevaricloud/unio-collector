from __future__ import annotations  # noqa: D100

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import date


@dataclass(frozen=True)
class AwsCollectionParityException:
    """A narrow, owned and time-bounded collection parity exception."""

    capability_id: str
    dimension: str
    reason: str
    architectural_justification: str
    owner: str
    created_on: date
    review_by: date

    def validation_errors(self, *, as_of: date) -> tuple[str, ...]:
        """Return fail-closed lifecycle and completeness errors."""
        errors = []
        if not self.capability_id or self.capability_id == "*":
            errors.append("Parity exceptions require one exact capability ID.")
        if not self.dimension or self.dimension == "*":
            errors.append("Parity exceptions require one exact dimension.")
        errors.extend(
            f"Parity exception {field_name} is required."
            for field_name in ("reason", "architectural_justification", "owner")
            if not str(getattr(self, field_name)).strip()
        )
        if self.created_on > as_of:
            errors.append("Parity exception creation date is in the future.")
        if self.review_by < as_of:
            errors.append("Parity exception is expired.")
        if self.review_by < self.created_on:
            errors.append("Parity exception review date predates creation.")
        return tuple(errors)

    def convert_to_dict(self) -> dict[str, Any]:
        """Return deterministic machine-readable exception metadata."""
        payload = asdict(self)
        payload["created_on"] = self.created_on.isoformat()
        payload["review_by"] = self.review_by.isoformat()
        return payload


__all__ = ["AwsCollectionParityException"]
