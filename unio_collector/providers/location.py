from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.providers.types import ProviderLocationType


@dataclass(frozen=True)
class ProviderLocation:
    """Provider-neutral cloud location such as a region or global scope."""

    provider_id: str
    location_id: str
    display_name: str
    location_type: ProviderLocationType = "unknown"
