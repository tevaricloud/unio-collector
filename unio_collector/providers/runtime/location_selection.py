from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderLocationSelection:
    """Provider-owned location selection for collection and reporting."""

    provider_id: str
    selected_locations: tuple[str, ...] = ()
    available_locations: tuple[str, ...] = ()
    selection_mode: str = "not_recorded"
    limitations: tuple[str, ...] = ()
