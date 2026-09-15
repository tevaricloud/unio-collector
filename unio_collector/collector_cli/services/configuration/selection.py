from __future__ import annotations  # noqa: D100

from dataclasses import replace
from typing import TYPE_CHECKING

from unio_collector.providers.aws.scanner_catalog import AwsProviderScannerCatalog
from unio_collector.scanners.registry.catalog import get_scanner
from unio_collector.scanners.selection import (
    apply_chargeable_scanner_gate,
    resolve_scanner_selection,
)

if TYPE_CHECKING:
    from unio_collector.collector.config.protocol import CollectionConfigProtocol
    from unio_collector.collector_cli.services.configuration.data import (
        CollectorFileConfig,
    )
    from unio_collector.scanners.scanner.selection import ScannerSelection


class CollectorScannerSelectionResolver:
    """Resolve scanner selection using collector-safe policies."""

    def resolve(
        self,
        args: object,
        file_config: CollectorFileConfig,
        config: CollectionConfigProtocol,
    ) -> ScannerSelection:
        """Build the final scanner selection for collector execution."""
        only_scanners = _string_list_arg(args, "only_scanner")
        enabled_scanners = _string_list_arg(args, "enable_scanner")
        disabled_scanners = _string_list_arg(args, "disable_scanner")
        provider_scanner_catalog = AwsProviderScannerCatalog().build()
        selection = resolve_scanner_selection(
            only_scanners=only_scanners,
            enabled_scanners=enabled_scanners,
            disabled_scanners=disabled_scanners,
            scanner_states=({} if config.provider_id != "aws" else dict(file_config.scanner_states)),
            scan_pillars=config.scan_pillars,
            provider_id=config.provider_id,
            provider_scanner_catalog=provider_scanner_catalog,
            product_id=config.product_id,
            product_selection_source=("cli" if getattr(args, "product", None) else "config" if file_config.product_id else None),
            allowed_out_of_product_scanners=_string_list_arg(
                args,
                "allow_out_of_product_scanner",
            ),
        )
        selection = self._apply_data_source_scanner_defaults(
            selection,
            config,
            only_scanners=only_scanners,
            disabled_scanners=disabled_scanners,
        )
        selection = self._apply_region_scope(selection, config)
        return apply_chargeable_scanner_gate(
            selection,
            allow_chargeable_scanners=config.allow_chargeable_scanners,
            provider_id=config.provider_id,
            provider_scanner_catalog=provider_scanner_catalog,
        )

    def _apply_data_source_scanner_defaults(
        self,
        selection: ScannerSelection,
        config: CollectionConfigProtocol,
        *,
        only_scanners: list[str],
        disabled_scanners: list[str],
    ) -> ScannerSelection:
        if config.provider_id != "aws" or not config.cur_paths:
            return selection
        if only_scanners:
            return selection
        scanner_id = "cur-data-export-attribution"
        if selection.product_id is not None:
            from unio_collector.products.collection import get_collection_product  # noqa: PLC0415

            if scanner_id not in get_collection_product(selection.product_id).allowed_scanner_ids:
                return selection
        if scanner_id in disabled_scanners:
            return selection
        enabled = set(selection.enabled_ids)
        disabled = set(selection.disabled_ids)
        enabled.add(scanner_id)
        disabled.discard(scanner_id)
        return replace(
            selection,
            enabled_ids=tuple(sorted(enabled)),
            disabled_ids=tuple(sorted(disabled)),
            disabled_reasons={key: value for key, value in selection.disabled_reasons.items() if key in disabled},
        )

    def _apply_region_scope(
        self,
        selection: ScannerSelection,
        config: CollectionConfigProtocol,
    ) -> ScannerSelection:
        if config.provider_id != "aws":
            return selection
        enabled = set(selection.enabled_ids)
        disabled = set(selection.disabled_ids)
        disabled_reasons = dict(selection.disabled_reasons)
        self._disable_global_scanners_when_needed(config, enabled, disabled, disabled_reasons)
        self._disable_regional_scanners_when_needed(
            config,
            enabled,
            disabled,
            disabled_reasons,
        )
        return replace(
            selection,
            enabled_ids=tuple(sorted(enabled)),
            disabled_ids=tuple(sorted(disabled)),
            disabled_reasons={
                scanner_id: disabled_reasons.get(
                    scanner_id,
                    "Scanner disabled by final scanner selection.",
                )
                for scanner_id in sorted(disabled)
            },
        )

    def _disable_global_scanners_when_needed(
        self,
        config: CollectionConfigProtocol,
        enabled: set[str],
        disabled: set[str],
        disabled_reasons: dict[str, str],
    ) -> None:
        if config.global_checks_enabled:
            return
        for scanner_id in list(enabled):
            if not get_scanner(scanner_id).supports_regions:
                enabled.remove(scanner_id)
                disabled.add(scanner_id)
                disabled_reasons[scanner_id] = "Scanner disabled because global checks were not included."

    def _disable_regional_scanners_when_needed(
        self,
        config: CollectionConfigProtocol,
        enabled: set[str],
        disabled: set[str],
        disabled_reasons: dict[str, str],
    ) -> None:
        if not config.global_only:
            return
        for scanner_id in list(enabled):
            if get_scanner(scanner_id).supports_regions:
                enabled.remove(scanner_id)
                disabled.add(scanner_id)
                disabled_reasons[scanner_id] = "Scanner disabled because the run is global-only."


def _string_list_arg(args: object, name: str) -> list[str]:
    return [str(value) for value in getattr(args, name, ()) or ()]


__all__ = ["CollectorScannerSelectionResolver"]
