from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderIdentity:
    """Stable identity for a supported cloud provider."""

    provider_id: str
    display_name: str
