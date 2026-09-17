"""Neutral standalone collection runtime configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.config.scan.profiles import FULL_SCAN_DETAIL_PROFILE, ScanDetailProfileResolver, ScanDetailProfileSource
from unio_collector.evidence.tagging.defaults import DEFAULT_COST_GROUP_TAGS

if TYPE_CHECKING:
    from decimal import Decimal
    from pathlib import Path

    from unio_collector.config.scan.detail.lower_precedence import OverriddenLowerPrecedenceValue
    from unio_collector.config.scan.detail.override_provenance import ScannerCliOverride
    from unio_collector.core.scan.period import ScanPeriod


@dataclass(frozen=True)
class CollectorRuntimeConfig:
    """Carry collection controls and explicit optional analysis inputs only."""

    profile: str | None
    days: int
    scan_period: ScanPeriod
    output: Path
    provider_id: str = "aws"
    azure_subscription_id: str | None = None
    entra_tenant_id: str | None = None
    gcp_project_id: str | None = None
    scan_preset: str | None = None
    scan_mode: str | None = None
    product_id: str | None = None
    scan_pillars: tuple[str, ...] = ()
    fixture: Path | None = None
    mode: str = "read-only"
    regions: tuple[str, ...] = ()
    regions_from_billing_enabled: bool = False
    global_checks_enabled: bool = True
    explicit_region_scope: bool = False
    global_only: bool = False
    region_scope_control_sources: dict[str, str] = field(default_factory=dict)
    scan_detail_profile: str = FULL_SCAN_DETAIL_PROFILE
    scan_detail_profile_explicit: bool = False
    scan_detail_profile_source: ScanDetailProfileSource = ScanDetailProfileSource.DEFAULT
    overridden_lower_precedence_values: tuple[OverriddenLowerPrecedenceValue, ...] = ()
    baseline_run_directory: Path | None = None
    allow_chargeable_scanners: bool = False
    service_usage_precheck_enabled: bool = True
    force_service_scanners: bool = False
    absolute_threshold: Decimal | None = None
    percent_threshold: Decimal | None = None
    default_currency: str = "USD"
    required_tags: tuple[str, ...] = ()
    scanner_options: dict[str, dict[str, object]] | None = None
    scanner_cli_overrides: tuple[ScannerCliOverride, ...] = ()
    report_date_format: str = "DD/MM/YYYY"
    report_currency: str = "USD"
    cost_grouping_enabled: bool = True
    cost_grouping_tags: tuple[str, ...] = DEFAULT_COST_GROUP_TAGS
    cur_paths: tuple[str, ...] = ()
    pricing_enrichment_enabled: bool = True
    pricing_enrichment_timeout_seconds: int = 30
    pricing_api_call_timeout_seconds: int = 2
    pricing_max_api_calls: int = 500
    pricing_worker_count: int = 4
    audit_ledger_redaction_enabled: bool = False
    runtime: AwsRuntimeConfig = field(default_factory=AwsRuntimeConfig)
    scan_detail_profile_resolution: dict[str, object] = field(init=False)
    analysis_defaults_deferred: bool = field(default=True, init=False)

    def __post_init__(self) -> None:
        """Resolve collection detail provenance without application configuration views."""
        source_is_explicit = self.scan_detail_profile_source is ScanDetailProfileSource.EXPLICIT_CLI
        if source_is_explicit != self.scan_detail_profile_explicit:
            msg = "Scan detail profile source is inconsistent with the explicit-selection compatibility field."
            raise ValueError(msg)
        scanner_options = self.scanner_options or {}
        object.__setattr__(self, "scanner_options", scanner_options)
        detail_resolution = ScanDetailProfileResolver().build_resolution_summary(
            scanner_options,
            self.scan_detail_profile,
            profile_is_explicit=self.scan_detail_profile_explicit,
            profile_source=self.scan_detail_profile_source,
            overridden_lower_precedence_values=self.overridden_lower_precedence_values,
            scanner_cli_overrides=self.scanner_cli_overrides,
        )
        if self.scan_detail_profile_explicit and (not bool(detail_resolution["canonical"])):
            mismatches = {str(value) for value in detail_resolution["coverage_mismatches"]}
            attributed = {f"{override['scanner_id']}.{override['option_name']}" for override in detail_resolution["higher_precedence_scanner_cli_overrides"]}
            unattributed = sorted(mismatches - attributed)
            if unattributed:
                msg = "Explicit scan detail profile did not resolve canonically: " + ", ".join(unattributed)
                raise ValueError(msg)
        object.__setattr__(self, "scan_detail_profile_resolution", detail_resolution)

    def get_region_selection_mode(self) -> str:
        """Return the compatible effective collection region mode."""
        if self.global_only:
            return "global_only"
        if self.regions_from_billing_enabled:
            return "billing_active_regions"
        if self.explicit_region_scope:
            return "explicit_regions"
        if self.fixture is not None:
            return "fixture_data"
        return "all_available_regions"

    def describe_region_scope(self) -> str:
        """Describe the effective scope using compatible region wording."""
        mode = self.get_region_selection_mode()
        if mode == "fixture_data":
            return "fixture data regions"
        if mode == "global_only":
            return "global checks only"
        if mode == "billing_active_regions":
            if self.regions:
                selected = ", ".join(self.regions)
                if self.global_checks_enabled:
                    return f"billing-active material regions ({selected}) plus global checks"
                return f"billing-active material regions ({selected})"
            if self.global_checks_enabled:
                return "billing-active material regions plus global checks"
            return "billing-active material regions"
        if mode == "explicit_regions":
            selected = ", ".join(self.regions) if self.regions else "no regional scope"
            if self.global_checks_enabled:
                return f"explicit regions ({selected}) plus global checks"
            return f"explicit regions ({selected})"
        if self.global_checks_enabled:
            return "all available service regions plus global checks"
        return "all available service regions"
