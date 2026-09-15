from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, cast

from unio_collector.aws.audit import ApiCallLedger
from unio_collector.aws.session import (
    AwsSessionConfig,
    create_audited_session,
    get_account_context,
)
from unio_collector.providers.aws.identity import AWS_PROVIDER
from unio_collector.providers.aws.scanner_catalog import AwsProviderScannerCatalog
from unio_collector.providers.runtime.contract import (
    ProviderAuthContext,
    ProviderEvidencePayload,
    ProviderLocationSelection,
    ProviderScannerExecutionContext,
    ProviderScopeSelection,
)
from unio_collector.scan_workflow.aws.scan.state import AwsScanState

if TYPE_CHECKING:
    from unio_collector.aws.audit import AuditedAwsSession
    from unio_collector.collector.config.protocol import CollectionConfigProtocol
    from unio_collector.providers.scanner_catalog import ProviderScannerCatalog


class AwsProviderRuntime:
    """AWS implementation of the shared provider runtime boundary."""

    @property
    def provider_id(self) -> str:
        """Return the AWS provider ID."""
        return AWS_PROVIDER.provider_id

    def create_scan_ledger(self, config: object) -> ApiCallLedger:
        """Create the AWS API call ledger for a scan."""
        scan_config = cast("CollectionConfigProtocol", config)
        return ApiCallLedger(
            redact_context=scan_config.audit_ledger_redaction_enabled,
        )

    def create_session(self, config: object, ledger: object) -> AuditedAwsSession:
        """Create the audited read-only AWS session for a scan."""
        scan_config = cast("CollectionConfigProtocol", config)
        api_ledger = cast("ApiCallLedger", ledger)
        return create_audited_session(
            AwsSessionConfig(profile=scan_config.profile),
            api_ledger,
            runtime_config=scan_config.runtime,
        )

    def resolve_identity(self, session: object) -> dict[str, object]:
        """Resolve AWS account identity metadata for the scan."""
        return get_account_context(cast("AuditedAwsSession", session))

    def build_scan_state(
        self,
        *,
        config: object,
        session: object,
        scope_id: str,
        ledger: object,
    ) -> AwsScanState:
        """Build AWS scan state for scanner execution."""
        return AwsScanState(
            config=cast("CollectionConfigProtocol", config),
            session=cast("AuditedAwsSession", session),
            account_id=scope_id,
            ledger=cast("ApiCallLedger", ledger),
        )

    def build_scanner_catalog(self) -> ProviderScannerCatalog:
        """Return AWS scanner catalog metadata through provider contracts."""
        return AwsProviderScannerCatalog().build()

    def build_auth_context(self, config: object) -> ProviderAuthContext:
        """Return typed AWS auth context without changing AWS session behavior."""
        scan_config = cast("CollectionConfigProtocol", config)
        return ProviderAuthContext(
            provider_id=self.provider_id,
            credential_source="aws-profile",
            principal_id=scan_config.profile,
        )

    def build_scope_selection(
        self,
        config: object,
        evidence: object | None = None,
    ) -> ProviderScopeSelection:
        """Return typed AWS scope selection for provider-neutral consumers."""
        del config, evidence
        return ProviderScopeSelection(
            provider_id=self.provider_id,
            scope_id="unknown-account",
            scope_type="account",
        )

    def build_location_selection(
        self,
        config: object,
        evidence: object | None = None,
    ) -> ProviderLocationSelection:
        """Return typed AWS location selection from existing scan config."""
        del evidence
        scan_config = cast("CollectionConfigProtocol", config)
        return ProviderLocationSelection(
            provider_id=self.provider_id,
            selected_locations=tuple(scan_config.regions),
            available_locations=tuple(scan_config.regions),
            selection_mode=scan_config.get_region_selection_mode(),
        )

    def build_scanner_execution_context(
        self,
        *,
        config: object,
        evidence: ProviderEvidencePayload,
    ) -> ProviderScannerExecutionContext:
        """Return typed AWS scanner context for provider-neutral consumers."""
        return ProviderScannerExecutionContext(
            provider_id=self.provider_id,
            auth=self.build_auth_context(config),
            scope=evidence.scope,
            locations=evidence.locations,
            evidence=evidence,
        )
