"""Read-only configuration consumed by shared collection runtime."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar, Protocol

if TYPE_CHECKING:
    from dataclasses import Field
    from decimal import Decimal
    from pathlib import Path

    from unio_collector.aws.client.config import AwsRuntimeConfig
    from unio_collector.config.scan.detail.lower_precedence import OverriddenLowerPrecedenceValue
    from unio_collector.config.scan.detail.override_provenance import ScannerCliOverride
    from unio_collector.config.scan.profiles import ScanDetailProfileSource
    from unio_collector.core.scan.period import ScanPeriod


class CollectionConfigProtocol(Protocol):
    """Allow application and collector dataclasses without private policy defaults."""

    __dataclass_fields__: ClassVar[dict[str, Field[Any]]]

    @property
    def profile(self) -> str | None:
        """Expose the configured profile value."""
        ...

    @property
    def days(self) -> int:
        """Expose the configured days value."""
        ...

    @property
    def scan_period(self) -> ScanPeriod:
        """Expose the configured scan period value."""
        ...

    @property
    def output(self) -> Path:
        """Expose the configured output value."""
        ...

    @property
    def provider_id(self) -> str:
        """Expose the configured provider id value."""
        ...

    @property
    def azure_subscription_id(self) -> str | None:
        """Expose the configured azure subscription id value."""
        ...

    @property
    def entra_tenant_id(self) -> str | None:
        """Expose the configured entra tenant id value."""
        ...

    @property
    def gcp_project_id(self) -> str | None:
        """Expose the configured gcp project id value."""
        ...

    @property
    def scan_preset(self) -> str | None:
        """Expose the configured scan preset value."""
        ...

    @property
    def scan_mode(self) -> str | None:
        """Expose the configured scan mode value."""
        ...

    @property
    def product_id(self) -> str | None:
        """Expose the configured product id value."""
        ...

    @property
    def scan_pillars(self) -> tuple[str, ...]:
        """Expose the configured scan pillars value."""
        ...

    @property
    def fixture(self) -> Path | None:
        """Expose the configured fixture value."""
        ...

    @property
    def mode(self) -> str:
        """Expose the configured mode value."""
        ...

    @property
    def regions(self) -> tuple[str, ...]:
        """Expose the configured regions value."""
        ...

    @property
    def regions_from_billing_enabled(self) -> bool:
        """Expose the configured regions from billing enabled value."""
        ...

    @property
    def global_checks_enabled(self) -> bool:
        """Expose the configured global checks enabled value."""
        ...

    @property
    def explicit_region_scope(self) -> bool:
        """Expose the configured explicit region scope value."""
        ...

    @property
    def global_only(self) -> bool:
        """Expose the configured global only value."""
        ...

    @property
    def region_scope_control_sources(self) -> dict[str, str]:
        """Expose the configured region scope control sources value."""
        ...

    @property
    def scan_detail_profile(self) -> str:
        """Expose the configured scan detail profile value."""
        ...

    @property
    def scan_detail_profile_explicit(self) -> bool:
        """Expose the configured scan detail profile explicit value."""
        ...

    @property
    def scan_detail_profile_source(self) -> ScanDetailProfileSource:
        """Expose the configured scan detail profile source value."""
        ...

    @property
    def overridden_lower_precedence_values(self) -> tuple[OverriddenLowerPrecedenceValue, ...]:
        """Expose the configured overridden lower precedence values value."""
        ...

    @property
    def baseline_run_directory(self) -> Path | None:
        """Expose the configured baseline run directory value."""
        ...

    @property
    def allow_chargeable_scanners(self) -> bool:
        """Expose the configured allow chargeable scanners value."""
        ...

    @property
    def service_usage_precheck_enabled(self) -> bool:
        """Expose the configured service usage precheck enabled value."""
        ...

    @property
    def force_service_scanners(self) -> bool:
        """Expose the configured force service scanners value."""
        ...

    @property
    def absolute_threshold(self) -> Decimal | None:
        """Expose the configured absolute threshold value."""
        ...

    @property
    def percent_threshold(self) -> Decimal | None:
        """Expose the configured percent threshold value."""
        ...

    @property
    def default_currency(self) -> str:
        """Expose the configured default currency value."""
        ...

    @property
    def required_tags(self) -> tuple[str, ...]:
        """Expose the configured required tags value."""
        ...

    @property
    def scanner_options(self) -> dict[str, dict[str, object]] | None:
        """Expose the configured scanner options value."""
        ...

    @property
    def scanner_cli_overrides(self) -> tuple[ScannerCliOverride, ...]:
        """Expose the configured scanner cli overrides value."""
        ...

    @property
    def report_date_format(self) -> str:
        """Expose the configured report date format value."""
        ...

    @property
    def report_currency(self) -> str:
        """Expose the configured report currency value."""
        ...

    @property
    def cost_grouping_enabled(self) -> bool:
        """Expose the configured cost grouping enabled value."""
        ...

    @property
    def cost_grouping_tags(self) -> tuple[str, ...]:
        """Expose the configured cost grouping tags value."""
        ...

    @property
    def cur_paths(self) -> tuple[str, ...]:
        """Expose the configured cur paths value."""
        ...

    @property
    def pricing_enrichment_enabled(self) -> bool:
        """Expose the configured pricing enrichment enabled value."""
        ...

    @property
    def pricing_enrichment_timeout_seconds(self) -> int:
        """Expose the configured pricing enrichment timeout seconds value."""
        ...

    @property
    def pricing_api_call_timeout_seconds(self) -> int:
        """Expose the configured pricing api call timeout seconds value."""
        ...

    @property
    def pricing_max_api_calls(self) -> int:
        """Expose the configured pricing max api calls value."""
        ...

    @property
    def pricing_worker_count(self) -> int:
        """Expose the configured pricing worker count value."""
        ...

    @property
    def audit_ledger_redaction_enabled(self) -> bool:
        """Expose the configured audit ledger redaction enabled value."""
        ...

    @property
    def runtime(self) -> AwsRuntimeConfig:
        """Expose the configured runtime value."""
        ...

    @property
    def scan_detail_profile_resolution(self) -> dict[str, object]:
        """Expose the configured scan detail profile resolution value."""
        ...

    def get_region_selection_mode(self) -> str:
        """Return the effective collection region selection mode."""
        ...

    def describe_region_scope(self) -> str:
        """Describe the effective collection region scope."""
        ...
