from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderCollectionLimitation:
    """Provider collection limitation that must not be treated as a clean result."""

    provider_id: str
    scope_id: str
    service_name: str
    reason: str
    permission: str | None = None
    location: str | None = None
