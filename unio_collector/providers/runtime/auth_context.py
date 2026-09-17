from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderAuthContext:
    """Typed provider authentication context for read-only runtime setup."""

    provider_id: str
    credential_source: str
    principal_id: str | None = None
    tenant_id: str | None = None
    metadata: tuple[tuple[str, str], ...] = ()
