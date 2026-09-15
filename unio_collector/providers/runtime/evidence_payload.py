from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.providers.runtime.collection_limitation import (
        ProviderCollectionLimitation,
    )
    from unio_collector.providers.runtime.location_selection import ProviderLocationSelection
    from unio_collector.providers.runtime.scope_selection import ProviderScopeSelection


@dataclass(frozen=True)
class ProviderEvidencePayload:
    """Provider-owned evidence payload consumed by provider-scoped scanners."""

    provider_id: str
    scope: ProviderScopeSelection
    locations: ProviderLocationSelection
    records: tuple[Any, ...] = ()
    limitations: tuple[ProviderCollectionLimitation, ...] = ()
    raw_summary: dict[str, Any] = field(default_factory=dict)
