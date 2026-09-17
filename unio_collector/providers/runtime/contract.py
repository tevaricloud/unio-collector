"""Provider runtime protocol and typed contract import surface.

Typed contracts cover auth context, scope selection, location selection,
limitations, scan result, report metadata adapter, and scanner execution context.
"""

from __future__ import annotations

from typing import Protocol

from unio_collector.providers.runtime.auth_context import ProviderAuthContext
from unio_collector.providers.runtime.collection_limitation import (
    ProviderCollectionLimitation,
)
from unio_collector.providers.runtime.evidence_payload import ProviderEvidencePayload
from unio_collector.providers.runtime.location_selection import ProviderLocationSelection
from unio_collector.providers.runtime.scan_result import ProviderScanResult
from unio_collector.providers.runtime.scanner_execution_context import (
    ProviderScannerExecutionContext,
)
from unio_collector.providers.runtime.scope_selection import ProviderScopeSelection
from unio_collector.scan_workflow.provider_execution.executor import ProviderScanExecutorProtocol

__all__ = [
    "ProviderAuthContext",
    "ProviderCollectionLimitation",
    "ProviderEvidencePayload",
    "ProviderLocationSelection",
    "ProviderRuntimeProtocol",
    "ProviderScanExecutorProtocol",
    "ProviderScanResult",
    "ProviderScannerExecutionContext",
    "ProviderScopeSelection",
]


class ProviderRuntimeProtocol(Protocol):
    """Provider-owned runtime boundary used by current AWS scan orchestration.

    AWS keeps its existing AWS compatibility placeholders below. Non-AWS runtimes use the
    typed provider contracts above for auth, scope, evidence, scanner execution,
    and report metadata preparation.
    """

    @property
    def provider_id(self) -> str:
        """Return the provider ID served by this runtime."""
        ...

    def create_scan_ledger(self, config: object) -> object:
        """Create provider-owned audit state from the current AWS config object."""
        ...

    def create_session(self, config: object, ledger: object) -> object:
        """Create the provider-owned session from AWS config and ledger objects."""
        ...

    def resolve_identity(self, session: object) -> dict[str, object]:
        """Resolve provider-owned identity metadata from the AWS session object."""
        ...

    def build_scan_state(
        self,
        *,
        config: object,
        session: object,
        scope_id: str,
        ledger: object,
    ) -> object:
        """Build the provider-owned mutable AWS scan state for scanner execution."""
        ...

    def build_scanner_catalog(self) -> object:
        """Return provider-owned scanner catalog metadata."""
        ...

    def build_auth_context(self, config: object) -> ProviderAuthContext:
        """Build typed provider authentication context."""
        ...

    def build_scope_selection(self, config: object, evidence: object | None = None) -> ProviderScopeSelection:
        """Build typed provider scope selection."""
        ...

    def build_location_selection(self, config: object, evidence: object | None = None) -> ProviderLocationSelection:
        """Build typed provider location selection."""
        ...

    def build_scanner_execution_context(
        self,
        *,
        config: object,
        evidence: ProviderEvidencePayload,
    ) -> ProviderScannerExecutionContext:
        """Build typed provider scanner execution context."""
        ...
