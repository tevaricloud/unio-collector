"""Runtime scan configuration package.

Public imports from ``unio_collector.config`` remain supported through lazy exports.
The facade stays lightweight so collector-only imports do not load report or
LLM modules unless those names are explicitly requested.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.config.metadata import MetadataConfigFile
    from unio_collector.config.runtime import (
        DEFAULT_OUTPUT_FORMATS,
        DEFAULT_REQUIRED_TAGS,
        SCAN_MODES,
        SUPPORTED_DATE_FORMATS,
        SUPPORTED_OUTPUT_FORMATS,
        ScanConfig,
        decimal_from_env,
        default_scan_config,
        ensure_output_dir,
    )
    from unio_collector.config.runtime_config.framework import (
        RuntimeFrameworkReadinessConfig,
    )
    from unio_collector.config.runtime_config.pricing import RuntimePricingConfig
    from unio_collector.config.runtime_config.reporting import RuntimeReportConfig
    from unio_collector.config.runtime_config.scan import RuntimeScanConfig
    from unio_collector.config.scan.detail.profile import (
        DEVELOPMENT_SCAN_DETAIL_PROFILE,
        FULL_SCAN_DETAIL_PROFILE,
        SCAN_DETAIL_PROFILE_IDS,
        SCAN_DETAIL_PROFILES,
        ScanDetailProfile,
    )
    from unio_collector.config.scan.detail.resolver import ScanDetailProfileResolver
    from unio_collector.config.scan.detail.selection import ScanDetailProfileSelection
    from unio_collector.config.scan.detail.source import ScanDetailProfileSource
    from unio_collector.config.scan.modes import (
        SCAN_MODE_IDS,
        normalize_scan_mode,
        resolve_scan_mode_pillars,
    )
    from unio_collector.config.scan.preset import (
        SCAN_PRESET_IDS,
        SCAN_PRESETS,
        ScanPreset,
    )
    from unio_collector.config.scan.preset_resolver import ScanPresetResolver

_EXPORTS = {
    "DEFAULT_OUTPUT_FORMATS": "unio_collector.config.runtime",
    "DEFAULT_REQUIRED_TAGS": "unio_collector.config.runtime",
    "SCAN_MODES": "unio_collector.config.runtime",
    "SUPPORTED_DATE_FORMATS": "unio_collector.config.runtime",
    "SUPPORTED_OUTPUT_FORMATS": "unio_collector.config.runtime",
    "ScanConfig": "unio_collector.config.runtime",
    "decimal_from_env": "unio_collector.config.runtime",
    "default_scan_config": "unio_collector.config.runtime",
    "ensure_output_dir": "unio_collector.config.runtime",
    "MetadataConfigFile": "unio_collector.config.metadata",
    "RuntimeFrameworkReadinessConfig": ("unio_collector.config.runtime_config.framework"),
    "RuntimePricingConfig": "unio_collector.config.runtime_config.pricing",
    "RuntimeReportConfig": "unio_collector.config.runtime_config.reporting",
    "RuntimeScanConfig": "unio_collector.config.runtime_config.scan",
    "DEVELOPMENT_SCAN_DETAIL_PROFILE": "unio_collector.config.scan.detail.profile",
    "FULL_SCAN_DETAIL_PROFILE": "unio_collector.config.scan.detail.profile",
    "SCAN_DETAIL_PROFILES": "unio_collector.config.scan.detail.profile",
    "SCAN_DETAIL_PROFILE_IDS": "unio_collector.config.scan.detail.profile",
    "ScanDetailProfile": "unio_collector.config.scan.detail.profile",
    "ScanDetailProfileResolver": "unio_collector.config.scan.detail.resolver",
    "ScanDetailProfileSelection": "unio_collector.config.scan.detail.selection",
    "ScanDetailProfileSource": "unio_collector.config.scan.detail.source",
    "SCAN_MODE_IDS": "unio_collector.config.scan.modes",
    "normalize_scan_mode": "unio_collector.config.scan.modes",
    "resolve_scan_mode_pillars": "unio_collector.config.scan.modes",
    "SCAN_PRESETS": "unio_collector.config.scan.preset",
    "SCAN_PRESET_IDS": "unio_collector.config.scan.preset",
    "ScanPreset": "unio_collector.config.scan.preset",
    "ScanPresetResolver": "unio_collector.config.scan.preset_resolver",
}

__all__ = [
    "DEFAULT_OUTPUT_FORMATS",
    "DEFAULT_REQUIRED_TAGS",
    "DEVELOPMENT_SCAN_DETAIL_PROFILE",
    "FULL_SCAN_DETAIL_PROFILE",
    "SCAN_DETAIL_PROFILES",
    "SCAN_DETAIL_PROFILE_IDS",
    "SCAN_MODES",
    "SCAN_MODE_IDS",
    "SCAN_PRESETS",
    "SCAN_PRESET_IDS",
    "SUPPORTED_DATE_FORMATS",
    "SUPPORTED_OUTPUT_FORMATS",
    "MetadataConfigFile",
    "RuntimeFrameworkReadinessConfig",
    "RuntimePricingConfig",
    "RuntimeReportConfig",
    "RuntimeScanConfig",
    "ScanConfig",
    "ScanDetailProfile",
    "ScanDetailProfileResolver",
    "ScanDetailProfileSelection",
    "ScanDetailProfileSource",
    "ScanPreset",
    "ScanPresetResolver",
    "decimal_from_env",
    "default_scan_config",
    "ensure_output_dir",
    "normalize_scan_mode",
    "resolve_scan_mode_pillars",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Return a public config export lazily."""
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(name)
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value
