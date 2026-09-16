"""Typed caller inputs for neutral collection configuration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from unio_collector.config.scan.profiles import FULL_SCAN_DETAIL_PROFILE, ScanDetailProfileSource

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.config.scan.detail.lower_precedence import OverriddenLowerPrecedenceValue
    from unio_collector.config.scan.detail.override_provenance import ScannerCliOverride


@dataclass(frozen=True, kw_only=True)
class CollectorConfigInput:
    """Carry explicit scope, runtime budgets and passive output metadata."""

    profile: str | None
    days: int | None = None
    months: int | None = None
    years: int | None = None
    date_from: str | None = None
    date_to: str | None = None
    output: str | Path
    fixture: str | Path | None
    provider_id: str | None = None
    azure_subscription_id: str | None = None
    entra_tenant_id: str | None = None
    gcp_project_id: str | None = None
    scan_preset: str | None = None
    scan_mode: str | None = None
    product_id: str | None = None
    scan_pillars: list[str] | tuple[str, ...] | None = None
    mode: str = "read-only"
    regions: list[str] | None = None
    regions_from_billing_enabled: bool = False
    global_checks_enabled: bool = True
    explicit_region_scope: bool = False
    global_only: bool = False
    region_scope_control_sources: dict[str, str] | None = None
    scan_detail_profile: str = FULL_SCAN_DETAIL_PROFILE
    scan_detail_profile_explicit: bool = False
    scan_detail_profile_source: ScanDetailProfileSource | str | None = None
    overridden_lower_precedence_values: tuple[OverriddenLowerPrecedenceValue, ...] = ()
    baseline_run_directory: str | Path | None = None
    allow_chargeable_scanners: bool = False
    service_usage_precheck_enabled: bool = True
    force_service_scanners: bool = False
    required_tags: list[str] | tuple[str, ...] | None = None
    scanner_options: dict[str, dict[str, object]] | None = None
    scanner_cli_overrides: tuple[ScannerCliOverride, ...] = ()
    date_format: str = "DD/MM/YYYY"
    currency: str = "USD"
    cost_grouping_enabled: bool = True
    cost_grouping_tags: list[str] | tuple[str, ...] | None = None
    cur_paths: list[str] | tuple[str, ...] | None = None
    pricing_enrichment_enabled: bool = True
    pricing_enrichment_timeout_seconds: int = 30
    pricing_api_call_timeout_seconds: int = 2
    pricing_max_api_calls: int = 500
    pricing_worker_count: int = 4
    audit_ledger_redaction_enabled: bool = False
