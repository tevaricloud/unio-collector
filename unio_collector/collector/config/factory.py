"""Build collection controls without resolving private analysis defaults."""

from __future__ import annotations

import os
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import TYPE_CHECKING

from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.collector.config.constants import SCAN_MODES, SUPPORTED_DATE_FORMATS
from unio_collector.collector.config.runtime import CollectorRuntimeConfig
from unio_collector.collector.provider import normalize_collector_provider_id
from unio_collector.config.scan.modes import normalize_scan_mode
from unio_collector.config.scan.profiles import ScanDetailProfileSource
from unio_collector.core.scan.period_resolver import ScanPeriodResolver
from unio_collector.evidence.tagging.defaults import DEFAULT_COST_GROUP_TAGS

if TYPE_CHECKING:
    from unio_collector.collector.config.input import CollectorConfigInput


class CollectorConfigFactory:
    """Resolve explicit collector inputs and validate operational limits."""

    def build(self, request: CollectorConfigInput, *, runtime: AwsRuntimeConfig | None = None) -> CollectorRuntimeConfig:
        """Keep private finding defaults absent from the standalone runtime."""
        scan_period = ScanPeriodResolver().resolve(
            days=request.days, months=request.months, years=request.years, date_from=request.date_from, date_to=request.date_to
        )
        if request.mode not in SCAN_MODES:
            msg = f"--mode must be one of: {', '.join(SCAN_MODES)}"
            raise ValueError(msg)
        if request.date_format not in SUPPORTED_DATE_FORMATS:
            msg = f"--date-format must be one of: {', '.join(SUPPORTED_DATE_FORMATS)}"
            raise ValueError(msg)
        self._validate_pricing(request)
        runtime_config = runtime or AwsRuntimeConfig()
        runtime_config.validate()
        resolved_detail_source = (
            ScanDetailProfileSource(request.scan_detail_profile_source)
            if request.scan_detail_profile_source is not None
            else (ScanDetailProfileSource.EXPLICIT_CLI if request.scan_detail_profile_explicit else ScanDetailProfileSource.DEFAULT)
        )
        return CollectorRuntimeConfig(
            provider_id=normalize_collector_provider_id(request.provider_id),
            azure_subscription_id=self._normalize_optional_string(request.azure_subscription_id),
            entra_tenant_id=self._normalize_optional_string(request.entra_tenant_id),
            gcp_project_id=self._normalize_optional_string(request.gcp_project_id),
            profile=request.profile,
            days=scan_period.duration_days,
            scan_period=scan_period,
            output=Path(request.output),
            scan_preset=request.scan_preset,
            scan_mode=normalize_scan_mode(request.scan_mode),
            product_id=request.product_id,
            scan_pillars=tuple(request.scan_pillars or ()),
            fixture=Path(request.fixture) if request.fixture else None,
            mode=request.mode,
            regions=tuple(request.regions or ()),
            regions_from_billing_enabled=request.regions_from_billing_enabled,
            global_checks_enabled=request.global_checks_enabled,
            explicit_region_scope=request.explicit_region_scope,
            global_only=request.global_only,
            region_scope_control_sources=dict(request.region_scope_control_sources or {}),
            scan_detail_profile=request.scan_detail_profile,
            scan_detail_profile_explicit=request.scan_detail_profile_explicit,
            scan_detail_profile_source=resolved_detail_source,
            overridden_lower_precedence_values=request.overridden_lower_precedence_values,
            baseline_run_directory=Path(request.baseline_run_directory) if request.baseline_run_directory else None,
            allow_chargeable_scanners=request.allow_chargeable_scanners,
            service_usage_precheck_enabled=request.service_usage_precheck_enabled,
            force_service_scanners=request.force_service_scanners,
            absolute_threshold=_explicit_decimal("UNIO_COLLECTOR_ABSOLUTE_THRESHOLD"),
            percent_threshold=_explicit_decimal("UNIO_COLLECTOR_PERCENT_THRESHOLD"),
            default_currency=os.getenv("UNIO_COLLECTOR_DEFAULT_CURRENCY", "USD").upper(),
            required_tags=tuple(request.required_tags or ()),
            scanner_options=request.scanner_options or {},
            scanner_cli_overrides=request.scanner_cli_overrides,
            report_date_format=request.date_format,
            report_currency=request.currency.upper(),
            cost_grouping_enabled=request.cost_grouping_enabled,
            cost_grouping_tags=tuple(request.cost_grouping_tags or DEFAULT_COST_GROUP_TAGS),
            cur_paths=tuple(str(path) for path in request.cur_paths or ()),
            pricing_enrichment_enabled=request.pricing_enrichment_enabled,
            pricing_enrichment_timeout_seconds=request.pricing_enrichment_timeout_seconds,
            pricing_api_call_timeout_seconds=request.pricing_api_call_timeout_seconds,
            pricing_max_api_calls=request.pricing_max_api_calls,
            pricing_worker_count=request.pricing_worker_count,
            audit_ledger_redaction_enabled=request.audit_ledger_redaction_enabled,
            runtime=runtime_config,
        )

    def _normalize_optional_string(self, value: object) -> str | None:
        if value in (None, ""):
            return None
        normalized = str(value).strip()
        return normalized or None

    def _validate_pricing(self, pricing: CollectorConfigInput) -> None:
        if pricing.pricing_enrichment_timeout_seconds <= 0:
            msg = "Pricing enrichment timeout must be a positive integer."
            raise ValueError(msg)
        if pricing.pricing_api_call_timeout_seconds <= 0:
            msg = "Pricing API call timeout must be a positive integer."
            raise ValueError(msg)
        if pricing.pricing_api_call_timeout_seconds > pricing.pricing_enrichment_timeout_seconds:
            msg = "Pricing API call timeout must be less than or equal to the overall pricing enrichment timeout."
            raise ValueError(msg)
        if pricing.pricing_max_api_calls <= 0:
            msg = "Pricing API call limit must be a positive integer."
            raise ValueError(msg)
        if pricing.pricing_worker_count <= 0:
            msg = "Pricing worker count must be a positive integer."
            raise ValueError(msg)


def _explicit_decimal(name: str) -> Decimal | None:
    """Retain only explicitly configured thresholds, including explicit zero."""
    value = os.getenv(name)
    if value is None:
        return None
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        msg = f"{name} must be a decimal value, got {value!r}"
        raise ValueError(msg) from exc
    if not result.is_finite():
        msg = f"{name} must be a finite decimal value."
        raise ValueError(msg)
    return result
