from __future__ import annotations  # noqa: D100

from dataclasses import replace
from typing import TYPE_CHECKING

from unio_collector.collector.config.factory import CollectorConfigFactory
from unio_collector.collector.config.input import CollectorConfigInput
from unio_collector.collector.config.presets import get_collection_preset
from unio_collector.collector.provider import normalize_collector_provider_id
from unio_collector.config.scan.detail.cli_override import LambdaScannerCliOverrideResolver
from unio_collector.config.scan.profiles import (
    FULL_SCAN_DETAIL_PROFILE,
    ScanDetailProfileResolver,
)

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.aws.client.config import AwsRuntimeConfig
    from unio_collector.collector.config.runtime import CollectorRuntimeConfig
    from unio_collector.collector_cli.services.configuration.data import (
        CollectorFileConfig,
    )
    from unio_collector.config.scan.detail.lower_precedence import (
        OverriddenLowerPrecedenceValue,
    )
    from unio_collector.config.scan.detail.override_provenance import ScannerCliOverride
    from unio_collector.config.scan.detail.selection import ScanDetailProfileSelection


class CollectorScanConfigBuilder:
    """Build the neutral collection configuration for collector execution."""

    def build(
        self,
        *,
        args: object,
        output: str | Path,
        file_config: CollectorFileConfig,
        scan_preset: str | None,
        scan_mode: str | None,
        scan_pillars: tuple[str, ...],
        regions: list[str],
        regions_from_billing: bool,
        global_checks_enabled: bool,
        explicit_region_scope: bool,
        region_scope_control_sources: dict[str, str],
        allow_chargeable_scanners: bool,
        cost_grouping_tags: tuple[str, ...],
    ) -> CollectorRuntimeConfig:
        """Build collection controls without private application defaults."""
        (
            scanner_options,
            scanner_cli_overrides,
            detail_selection,
            overridden_lower_precedence_values,
        ) = self._build_scanner_options_resolution(args, file_config, scan_preset)
        return CollectorConfigFactory().build(
            CollectorConfigInput(
                provider_id=normalize_collector_provider_id(getattr(args, "provider", None) or file_config.provider_id),
                azure_subscription_id=getattr(args, "azure_subscription_id", None) or file_config.azure_subscription_id,
                entra_tenant_id=getattr(args, "entra_tenant_id", None) or file_config.entra_tenant_id,
                gcp_project_id=getattr(args, "gcp_project_id", None) or file_config.gcp_project_id,
                profile=getattr(args, "profile", None),
                days=getattr(args, "days", None),
                months=getattr(args, "months", None),
                years=getattr(args, "years", None),
                date_from=getattr(args, "date_from", None),
                date_to=getattr(args, "date_to", None),
                output=output,
                fixture=getattr(args, "fixture", None),
                scan_preset=scan_preset,
                scan_mode=scan_mode,
                product_id=getattr(args, "product", None) or file_config.product_id,
                scan_pillars=scan_pillars,
                mode=getattr(args, "mode", None) or file_config.mode or "read-only",
                regions=regions,
                regions_from_billing_enabled=regions_from_billing,
                global_checks_enabled=global_checks_enabled,
                explicit_region_scope=explicit_region_scope,
                region_scope_control_sources=region_scope_control_sources,
                global_only=bool(getattr(args, "global_only", False)),
                scan_detail_profile=detail_selection.profile_id,
                scan_detail_profile_explicit=detail_selection.explicit_cli_selection,
                scan_detail_profile_source=detail_selection.profile_source,
                overridden_lower_precedence_values=overridden_lower_precedence_values,
                allow_chargeable_scanners=allow_chargeable_scanners,
                service_usage_precheck_enabled=file_config.service_usage_precheck_enabled,
                force_service_scanners=bool(getattr(args, "force_service_scanners", False)) or file_config.force_service_scanners,
                required_tags=tuple(getattr(args, "required_tag", ()) or ()) or file_config.required_tags,
                scanner_options=scanner_options,
                scanner_cli_overrides=scanner_cli_overrides,
                date_format=file_config.date_format,
                currency=file_config.currency,
                cost_grouping_enabled=file_config.cost_grouping_enabled,
                cost_grouping_tags=cost_grouping_tags,
                cur_paths=tuple(getattr(args, "cur_path", ()) or ()) or file_config.cur_paths,
                pricing_enrichment_enabled=file_config.pricing_enrichment_enabled,
                pricing_enrichment_timeout_seconds=file_config.pricing_enrichment_timeout_seconds,
                pricing_api_call_timeout_seconds=file_config.pricing_api_call_timeout_seconds,
                pricing_max_api_calls=file_config.pricing_max_api_calls,
                pricing_worker_count=file_config.pricing_worker_count,
            ),
            runtime=self._build_runtime(args, file_config),
        )

    def _build_scanner_options(
        self,
        args: object,
        file_config: CollectorFileConfig,
        scan_preset: str | None,
    ) -> dict[str, dict[str, object]]:
        options, _, _, _ = self._build_scanner_options_resolution(
            args,
            file_config,
            scan_preset,
        )
        return options

    def _build_scanner_options_resolution(
        self,
        args: object,
        file_config: CollectorFileConfig,
        scan_preset: str | None,
    ) -> tuple[
        dict[str, dict[str, object]],
        tuple[ScannerCliOverride, ...],
        ScanDetailProfileSelection,
        tuple[OverriddenLowerPrecedenceValue, ...],
    ]:
        """Build collector options and scanner CLI-override provenance."""
        profile_resolver = ScanDetailProfileResolver()
        preset = get_collection_preset(scan_preset)
        cli_detail_profile = getattr(args, "scan_detail_profile", None)
        file_options = {scanner_id: dict(options) for scanner_id, options in file_config.scanner_options.items()}
        selection = profile_resolver.resolve_selection(
            cli_profile=cli_detail_profile,
            config_profile=file_config.detail_profile,
            config_profile_is_explicit=(file_config.has_configured_value("scan.detail_profile") or file_config.detail_profile != FULL_SCAN_DETAIL_PROFILE),
            preset_profile=getattr(preset, "detail_profile", None),
        )
        profile_resolution = profile_resolver.resolve_options_with_audit(
            file_options,
            selection,
        )
        options = profile_resolution.options
        scanner_cli_overrides = LambdaScannerCliOverrideResolver().apply(
            args,
            options,
        )
        return (
            options,
            scanner_cli_overrides,
            selection,
            profile_resolution.overridden_lower_precedence_values,
        )

    def _build_runtime(
        self,
        args: object,
        file_config: CollectorFileConfig,
    ) -> AwsRuntimeConfig:
        runtime = file_config.runtime.with_overrides(
            max_workers=getattr(args, "scan_max_workers", None),
            scanner_max_workers=getattr(args, "scanner_max_workers", None),
            max_pool_connections=getattr(args, "aws_max_pool_connections", None),
            total_max_attempts=getattr(args, "aws_total_max_attempts", None),
            connect_timeout_seconds=getattr(args, "aws_connect_timeout_seconds", None),
            read_timeout_seconds=getattr(args, "aws_read_timeout_seconds", None),
            record_aws_cassette=getattr(args, "record_aws_cassette", None),
            replay_aws_cassette=getattr(args, "replay_aws_cassette", None),
            confirm_live_aws_recording=bool(
                getattr(args, "confirm_live_aws_recording", False),
            ),
        )
        if bool(getattr(args, "runtime_diagnostics", False)):
            runtime = replace(
                runtime,
                diagnostics=replace(runtime.diagnostics, enabled=True),
            )
            runtime.validate()
        return runtime


__all__ = ["CollectorScanConfigBuilder"]
