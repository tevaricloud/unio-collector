from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderScopeSelection:
    """Explicit provider scope selected for a scan."""

    provider_id: str
    scope_id: str
    scope_type: str
    tenant_id: str | None = None
    display_label: str = ""
