from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

from unio_collector.providers.types import normalize_object_pairs

if TYPE_CHECKING:
    from unio_collector.providers.location import ProviderLocation
    from unio_collector.providers.scope import ProviderAccountScope


@dataclass(frozen=True)
class ProviderFindingMetadata:
    """Provider metadata for deterministic findings."""

    provider_id: str
    scope: ProviderAccountScope
    location: ProviderLocation
    service_name: str = ""
    native_resource_type: str = ""
    native_resource_id: str = ""
    native_metadata: tuple[tuple[str, object], ...] = ()

    def __post_init__(self) -> None:
        """Normalize immutable provider-native finding metadata."""
        object.__setattr__(
            self,
            "native_metadata",
            normalize_object_pairs(self.native_metadata),
        )
