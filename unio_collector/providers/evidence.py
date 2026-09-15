from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

from unio_collector.providers.types import (
    ProviderCollectionStatus,
    normalize_object_pairs,
    normalize_string_tuple,
)


@dataclass(frozen=True)
class ProviderEvidenceMetadata:
    """Collection metadata attached to normalized provider evidence."""

    provider_id: str
    evidence_source: str
    collection_status: ProviderCollectionStatus
    limitations: tuple[str, ...] = ()
    permissions_observed: tuple[str, ...] = ()
    collected_at: str | None = None
    scan_context: tuple[tuple[str, object], ...] = ()

    def __post_init__(self) -> None:
        """Normalize immutable evidence metadata collections."""
        object.__setattr__(self, "limitations", normalize_string_tuple(self.limitations))
        object.__setattr__(
            self,
            "permissions_observed",
            normalize_string_tuple(self.permissions_observed),
        )
        object.__setattr__(
            self,
            "scan_context",
            normalize_object_pairs(self.scan_context),
        )
