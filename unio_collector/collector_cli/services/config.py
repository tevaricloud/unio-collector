from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.collector.config.presets import get_collection_preset
from unio_collector.collector_cli.console import print_warning
from unio_collector.collector_cli.services.configuration.builder import (
    CollectorScanConfigBuilder,
)
from unio_collector.collector_cli.services.configuration.data import (
    CollectorFileConfig,
)
from unio_collector.collector_cli.services.configuration.loader import (
    CollectorConfigFileLoader,
)
from unio_collector.collector_cli.services.configuration.result import (
    CollectorConfigResult,
)
from unio_collector.collector_cli.services.configuration.selection import (
    CollectorScannerSelectionResolver,
)
from unio_collector.config.default_resolver import DefaultConfigResolver
from unio_collector.config.scan.modes import normalize_scan_mode, resolve_scan_mode_pillars
from unio_collector.scanners.pillars import normalize_scan_pillars

if TYPE_CHECKING:
    from pathlib import Path


class CollectorConfigResolver:
    """Resolve collector-safe runtime configuration."""

    def __init__(self, console: object) -> None:
        """Store the output console."""
        self.console = console

    def resolve(self, args: object, *, output: str | Path) -> CollectorConfigResult:
        """Resolve the scan config and scanner selection for collection."""
        file_config = self.load_file_config(args)
        scan_preset = self._resolve_preset(args, file_config)
        preset = get_collection_preset(scan_preset)
        scan_mode = self._resolve_scan_mode(args, file_config, preset)
        scan_pillars = self._resolve_scan_pillars(
            args,
            file_config,
            preset,
            scan_mode,
        )
        config = CollectorScanConfigBuilder().build(
            args=args,
            output=output,
            file_config=file_config,
            scan_preset=scan_preset,
            scan_mode=scan_mode,
            scan_pillars=scan_pillars,
            regions=self._resolve_regions(args, file_config),
            regions_from_billing=self._resolve_regions_from_billing(
                args,
                file_config,
                preset,
            ),
            global_checks_enabled=self._resolve_global_checks(
                args,
                file_config,
                preset,
            ),
            explicit_region_scope=self._has_explicit_region_scope(
                args,
                file_config,
                preset,
            ),
            region_scope_control_sources=self._build_region_scope_control_sources(
                args,
                file_config,
                preset,
            ),
            allow_chargeable_scanners=self._resolve_chargeable(
                args,
                file_config,
                preset,
            ),
            cost_grouping_tags=self._resolve_cost_grouping_tags(args, file_config),
        )
        selection = CollectorScannerSelectionResolver().resolve(
            args,
            file_config,
            config,
        )
        return CollectorConfigResult(
            config=config,
            selection=selection,
            file_config=file_config,
        )

    def load_file_config(self, args: object) -> CollectorFileConfig:
        """Load optional collector-safe YAML config."""
        resolver = DefaultConfigResolver()
        if resolver.detect_missing_default_config() and not getattr(
            args,
            "quiet",
            False,
        ):
            self._print_warning(resolver.build_missing_default_warning())
        config_path = resolver.resolve_config_path(getattr(args, "config", None))
        if config_path is None:
            return CollectorFileConfig()
        return CollectorConfigFileLoader(config_path).load(
            strict=bool(getattr(args, "strict_config", False)),
        )

    def _resolve_regions(
        self,
        args: object,
        file_config: CollectorFileConfig,
    ) -> list[str]:
        regions: list[str] = list(getattr(args, "region", ()) or ())
        csv_regions = getattr(args, "regions", None)
        if csv_regions:
            regions.extend(part.strip() for part in str(csv_regions).split(",") if part.strip())
        if not regions:
            regions = list(file_config.regions)
        if any(region.strip().lower() == "global" for region in regions):
            msg = "Region options accept AWS region names only. Do not include 'global'."
            raise ValueError(msg)
        return sorted(dict.fromkeys(region.strip() for region in regions if region))

    def _resolve_preset(
        self,
        args: object,
        file_config: CollectorFileConfig,
    ) -> str | None:
        preset = getattr(args, "preset", None) or file_config.preset
        resolved = get_collection_preset(preset)
        return resolved.preset_id if resolved else None

    def _resolve_scan_mode(
        self,
        args: object,
        file_config: CollectorFileConfig,
        preset: object,
    ) -> str | None:
        value = getattr(args, "scan_mode", None) or file_config.scan_mode
        if not value:
            value = getattr(preset, "scan_mode", None)
        return normalize_scan_mode(value)

    def _resolve_scan_pillars(
        self,
        args: object,
        file_config: CollectorFileConfig,
        preset: object,
        scan_mode: str | None,
    ) -> tuple[str, ...]:
        cli_values = tuple(getattr(args, "scan_pillar", ()) or ())
        if cli_values:
            return normalize_scan_pillars(cli_values)
        if file_config.pillars:
            return file_config.pillars
        preset_pillars = getattr(preset, "scan_pillars", None)
        if preset_pillars is not None:
            return normalize_scan_pillars(preset_pillars)
        return resolve_scan_mode_pillars(scan_mode) or file_config.pillars

    def _resolve_regions_from_billing(
        self,
        args: object,
        file_config: CollectorFileConfig,
        preset: object,
    ) -> bool:
        if bool(getattr(args, "regions_from_billing", False)):
            return True
        if file_config.has_configured_value("scan.regions_from_billing"):
            return file_config.regions_from_billing
        preset_value = getattr(preset, "regions_from_billing", None)
        if preset_value is not None:
            return bool(preset_value)
        return file_config.regions_from_billing

    def _resolve_global_checks(
        self,
        args: object,
        file_config: CollectorFileConfig,
        preset: object,
    ) -> bool:
        if bool(getattr(args, "global_only", False)):
            return True
        if self._resolve_regions_from_billing(args, file_config, preset):
            return True
        if getattr(args, "region", ()) or getattr(args, "regions", None):
            return bool(getattr(args, "include_global", False))
        return True

    def _has_explicit_region_scope(
        self,
        args: object,
        file_config: CollectorFileConfig,
        preset: object,
    ) -> bool:
        return bool(
            getattr(args, "region", ())
            or getattr(args, "regions", None)
            or file_config.regions
            or self._resolve_regions_from_billing(args, file_config, preset),
        )

    def _resolve_chargeable(
        self,
        args: object,
        file_config: CollectorFileConfig,
        preset: object,
    ) -> bool:
        if bool(getattr(args, "allow_chargeable_scanners", False)):
            return True
        if file_config.has_configured_value(
            "scan.allow_chargeable_scanners",
        ) or file_config.has_configured_value("scan.allow_chargeable_scans"):
            return file_config.allow_chargeable_scanners
        preset_value = getattr(preset, "allow_chargeable_scanners", None)
        if preset_value is not None:
            return bool(preset_value)
        return file_config.allow_chargeable_scanners

    def _build_region_scope_control_sources(
        self,
        args: object,
        file_config: CollectorFileConfig,
        preset: object,
    ) -> dict[str, str]:
        regions_source = "default"
        if getattr(args, "region", ()) or getattr(args, "regions", None):
            regions_source = "cli"
        elif file_config.has_configured_value("scan.regions"):
            regions_source = "yaml"

        billing_source = "default"
        if bool(getattr(args, "regions_from_billing", False)):
            billing_source = "cli"
        elif file_config.has_configured_value("scan.regions_from_billing"):
            billing_source = "yaml"
        elif getattr(preset, "regions_from_billing", None) is not None:
            billing_source = "preset"

        global_source = "default"
        if bool(getattr(args, "global_only", False)):
            global_source = "cli_global_only"
        elif bool(getattr(args, "include_global", False)):
            global_source = "cli_include_global"
        elif self._resolve_regions_from_billing(args, file_config, preset):
            global_source = billing_source
        return {
            "requested_regions": regions_source,
            "regions_from_billing": billing_source,
            "global_checks": global_source,
        }

    def _resolve_cost_grouping_tags(
        self,
        args: object,
        file_config: CollectorFileConfig,
    ) -> tuple[str, ...]:
        raw = getattr(args, "group_costs_by", None)
        if not raw:
            return file_config.cost_grouping_tags
        tags = tuple(part.strip() for part in str(raw).split(",") if part.strip())
        if not tags:
            msg = "--group-costs-by must include at least one tag key."
            raise ValueError(msg)
        return tags

    def _print_warning(self, message: str) -> None:
        print_warning(self.console, f"Warning: {message}")


__all__ = [
    "CollectorConfigFileLoader",
    "CollectorConfigResolver",
    "CollectorConfigResult",
    "CollectorFileConfig",
]
