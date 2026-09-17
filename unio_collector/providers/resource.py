from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

from unio_collector.providers.types import normalize_string_pairs

if TYPE_CHECKING:
    from unio_collector.providers.location import ProviderLocation
    from unio_collector.providers.scope import ProviderAccountScope


@dataclass(frozen=True)
class ProviderResourceIdentity:
    """Provider-neutral identity for a resource observed during assessment."""

    provider_id: str
    scope: ProviderAccountScope
    location: ProviderLocation
    service_name: str
    canonical_resource_type: str
    native_resource_type: str
    resource_id: str
    resource_name: str | None = None
    tags: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        """Normalize immutable resource tags."""
        object.__setattr__(self, "tags", normalize_string_pairs(self.tags))
