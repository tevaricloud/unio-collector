from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.providers.runtime.auth_context import ProviderAuthContext
    from unio_collector.providers.runtime.evidence_payload import ProviderEvidencePayload
    from unio_collector.providers.runtime.location_selection import ProviderLocationSelection
    from unio_collector.providers.runtime.scope_selection import ProviderScopeSelection


@dataclass(frozen=True)
class ProviderScannerExecutionContext:
    """Typed scanner execution context for provider-scoped scanner workflows."""

    provider_id: str
    auth: ProviderAuthContext
    scope: ProviderScopeSelection
    locations: ProviderLocationSelection
    evidence: ProviderEvidencePayload
