from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.providers.runtime.auth_context import ProviderAuthContext
    from unio_collector.providers.runtime.evidence_payload import ProviderEvidencePayload
    from unio_collector.providers.runtime.location_selection import ProviderLocationSelection
    from unio_collector.providers.runtime.scope_selection import ProviderScopeSelection


@dataclass(frozen=True)
class ProviderScanResult:
    """Typed provider scan result before report workflow adaptation."""

    provider_id: str
    auth: ProviderAuthContext
    scope: ProviderScopeSelection
    locations: ProviderLocationSelection
    evidence: ProviderEvidencePayload
    findings: tuple[Any, ...] = ()
    scanner_results: tuple[Any, ...] = ()
    summary: dict[str, Any] = field(default_factory=dict)
