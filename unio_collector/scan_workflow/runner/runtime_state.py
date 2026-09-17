from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from unio_collector.scan_workflow.regions import AwsRegionScope

if TYPE_CHECKING:
    from unio_collector.aws.audit import ApiCallLedger
    from unio_collector.aws.cache import AwsScanCache
    from unio_collector.aws.client.config import AwsRuntimeConfig
    from unio_collector.aws.session import AuditedAwsSession
    from unio_collector.collector.config.protocol import CollectionConfigProtocol
    from unio_collector.scan_workflow.aws.scan.state import AwsScanState


@dataclass(frozen=True)
class ScannerRuntimeStateView:
    """Narrow read-only access to scan state for runtime collaborators."""

    _state: AwsScanState

    @property
    def config(self) -> CollectionConfigProtocol:
        """Return the immutable scan configuration for runtime collaborators."""
        return self._state.config

    @property
    def runtime_config(self) -> AwsRuntimeConfig:
        """Return AWS runtime settings without exposing mutable scan state."""
        return self._state.config.runtime

    @property
    def session(self) -> AuditedAwsSession:
        """Return the audited read-only AWS session."""
        return self._state.session

    @property
    def account_id(self) -> str:
        """Return the scanned AWS account ID."""
        return self._state.account_id

    @property
    def ledger(self) -> ApiCallLedger:
        """Return the read-only API call ledger."""
        return self._state.ledger

    @property
    def cache(self) -> AwsScanCache:
        """Return the shared AWS scan cache."""
        return self._state.cache

    @property
    def collection_diagnostics(self) -> Any:  # noqa: ANN401
        """Return optional collection diagnostics from the audited session."""
        return getattr(self._state.session, "collection_diagnostics", None)

    def get_selected_regions(self) -> list[str] | None:
        """Return explicit regions or account-enabled default regions."""
        return self.get_region_scope().get_selected_regions()

    def get_service_regions(self, service_name: str) -> list[str]:
        """Return service regions filtered by account-enabled region scope."""
        return self.get_region_scope().get_service_regions(service_name)

    def get_region_scope_summary(self) -> dict[str, Any]:
        """Return bundle-safe region scope metadata."""
        return self.get_region_scope().convert_to_summary()

    def has_explicit_region_scope(self) -> bool:
        """Return whether the scan was configured with explicit regions."""
        explicit = getattr(self.config, "explicit_region_scope", None)
        if explicit is not None:
            return bool(explicit)
        return bool(self.config.regions)

    def get_region_scope(self) -> AwsRegionScope:
        """Return the shared lazy AWS region scope resolver."""
        if self._state.region_scope is None:
            self._state.region_scope = AwsRegionScope(
                session=self.session,
                account_id=self.account_id,
                explicit_regions=(list(self.config.regions) if self.has_explicit_region_scope() and self.config.regions else None),
            )
            if hasattr(self.session, "region_scope"):
                self.session.region_scope = self._state.region_scope
        return self._state.region_scope

    def get_scanner_option(self, scanner_id: str, key: str, default: object) -> object:
        """Return one scanner option value from resolved scan configuration."""
        options = self.config.scanner_options or {}
        return options.get(scanner_id, {}).get(key, default)
