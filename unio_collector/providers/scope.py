from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.providers.types import ProviderScopeType


@dataclass(frozen=True)
class ProviderAccountScope:
    """Provider-neutral account, subscription, tenant, or organization scope."""

    provider_id: str
    scope_id: str
    scope_type: ProviderScopeType = "account"
    tenant_id: str | None = None
    display_label: str = ""
