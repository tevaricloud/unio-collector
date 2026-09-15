from __future__ import annotations  # noqa: D100

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class DegradationContext:
    """Optional structured context already known at an API failure site."""

    resource_type: str | None = None
    resource_id: str | None = None
    affected_fields: tuple[str, ...] = ()
    evidence_categories: tuple[str, ...] = ()
    requested_account_id: str | None = None
    requested_region: str | None = None
    safe_scope: str | None = None

    def convert_to_dict(self) -> dict[str, object]:
        """Return deterministic JSON-compatible context."""
        return asdict(self)


__all__ = ["DegradationContext"]
