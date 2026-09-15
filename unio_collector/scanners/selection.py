from __future__ import annotations  # noqa: D100

from importlib import import_module
from typing import TYPE_CHECKING, Any, cast

from unio_collector.products.collection import get_collection_product
from unio_collector.providers.aws.identity import AWS_PROVIDER
from unio_collector.scanners.chargeable_scanner_block import (
    CHARGEABLE_SCANNER_CLI_OPTION,
    CHARGEABLE_SCANNER_CONFIG_KEY,
    ChargeableScannerBlock,
)
from unio_collector.scanners.errors import build_unknown_scanner_ids_message
from unio_collector.scanners.pillars import (
    DEFAULT_SCANNER_PILLAR_POLICY,
    SCAN_PILLAR_IDS,
    normalize_scan_pillars,
)
from unio_collector.scanners.registry.definitions import SCANNERS
from unio_collector.scanners.scanner.selection import ScannerSelection

AWS_PROVIDER_ID = AWS_PROVIDER.provider_id
PROVIDER_SELECTION_MODULE = "unio_collector.providers.selection"

if TYPE_CHECKING:
    from unio_collector.providers.scanner_catalog import ProviderScannerCatalog
    from unio_collector.scanners.scanner.definition import ScannerDefinition


def resolve_scanner_selection(  # noqa: C901, D103
    *,
    only_scanners: list[str] | None = None,
    enabled_scanners: list[str] | None = None,
    disabled_scanners: list[str] | None = None,
    scanner_states: dict[str, bool] | None = None,
    scan_pillars: tuple[str, ...] | list[str] | None = None,
    provider_id: str | None = None,
    provider_scanner_catalog: ProviderScannerCatalog | None = None,
    product_id: str | None = None,
    product_selection_source: str | None = None,
    allowed_out_of_product_scanners: list[str] | tuple[str, ...] | None = None,
) -> ScannerSelection:
    only = only_scanners or []
    enable = enabled_scanners or []
    disable = disabled_scanners or []
    configured_states = scanner_states or {}
    out_of_product_gates = set(allowed_out_of_product_scanners or ())
    resolved_catalog = resolve_provider_scanner_catalog(
        provider_id=provider_id,
        provider_scanner_catalog=provider_scanner_catalog,
    )
    scanner_definitions = scanner_definitions_for_catalog(resolved_catalog)
    _validate_provider_scanner_ids(
        [*only, *enable, *disable, *configured_states],
        available_ids=set(scanner_definitions),
        provider_id=provider_id or resolved_catalog.provider_id,
    )
    selected_pillars = normalize_scan_pillars(scan_pillars)
    product = get_collection_product(product_id) if product_id else None
    if product is not None and (provider_id or resolved_catalog.provider_id) not in product.supported_provider_ids:
        msg = f"Product {product.product_id} supports provider aws only."
        raise ValueError(msg)

    all_ids = set(scanner_definitions)
    disabled_reasons: dict[str, str] = {}
    pillar_filter_applied = False
    pillar_filter_bypass_reason = ""
    product_ids = set(product.allowed_scanner_ids) if product else set()
    explicit_requested = set(only or enable)
    if product:
        invalid_config_enables = sorted(scanner_id for scanner_id, is_enabled in configured_states.items() if is_enabled and scanner_id not in product_ids)
        if invalid_config_enables:
            raise ValueError(
                f"Product {product.product_id} does not allow YAML to enable out-of-product scanners: "
                + ", ".join(invalid_config_enables)
                + ". Use --enable-scanner with --allow-out-of-product-scanner for each scanner."
            )
        outside = explicit_requested - product_ids
        missing_gates = sorted(outside - out_of_product_gates)
        unused_gates = sorted(out_of_product_gates - outside)
        if missing_gates:
            raise ValueError("Out-of-product scanners require matching --allow-out-of-product-scanner authorization: " + ", ".join(missing_gates) + ".")
        if unused_gates:
            raise ValueError("Out-of-product scanner authorization requires an explicit --enable-scanner or --only-scanner: " + ", ".join(unused_gates) + ".")
    elif out_of_product_gates:
        msg = "--allow-out-of-product-scanner requires an explicitly selected product."
        raise ValueError(msg)

    if only:
        enabled = set(only)
        if selected_pillars:
            pillar_filter_bypass_reason = "Scan pillar filtering was not applied because --only-scanner requests an exact scanner set."
        disabled_reasons.update(
            dict.fromkeys(
                all_ids - enabled,
                "Scanner excluded by --only-scanner selection.",
            ),
        )
    else:
        enabled = (
            set(product.default_scanner_ids)
            if product
            else {scanner_id for scanner_id, definition in scanner_definitions.items() if definition.default_enabled}
        )
        disabled_reasons.update(
            {
                scanner_id: "Scanner disabled by default registry setting."
                for scanner_id, definition in scanner_definitions.items()
                if not definition.default_enabled
            },
        )
        for scanner_id, is_enabled in configured_states.items():
            if is_enabled:
                enabled.add(scanner_id)
                disabled_reasons.pop(scanner_id, None)
            else:
                enabled.discard(scanner_id)
                disabled_reasons[scanner_id] = "Scanner disabled by configuration file."
        enabled.update(enable)
        for scanner_id in enable:
            disabled_reasons.pop(scanner_id, None)
        if selected_pillars:
            allowed_by_pillar = _get_pillar_allowed_scanner_ids(
                resolved_catalog,
                selected_pillars,
                provider_id=provider_id,
            )
            for scanner_id in sorted(enabled - allowed_by_pillar):
                enabled.remove(scanner_id)
                disabled_reasons[scanner_id] = f"Scanner excluded because it is outside the selected scan pillars: {', '.join(selected_pillars)}."
            pillar_filter_applied = True
            for scanner_id in enable:
                enabled.add(scanner_id)
                disabled_reasons.pop(scanner_id, None)

    enabled.difference_update(disable)
    for scanner_id in disable:
        disabled_reasons[scanner_id] = "Scanner disabled by CLI option."
    disabled = all_ids - enabled

    return ScannerSelection(
        enabled_ids=tuple(sorted(enabled)),
        disabled_ids=tuple(sorted(disabled)),
        selected_pillars=selected_pillars,
        pillar_filter_applied=pillar_filter_applied,
        pillar_filter_bypass_reason=pillar_filter_bypass_reason,
        pillar_policy_summary=_build_pillar_policy_summary(
            resolved_catalog,
            selected_pillars,
            provider_id=provider_id,
            filter_applied=pillar_filter_applied,
            bypass_reason=pillar_filter_bypass_reason,
        ),
        disabled_reasons={
            scanner_id: disabled_reasons.get(
                scanner_id,
                "Scanner disabled by final scanner selection.",
            )
            for scanner_id in sorted(disabled)
        },
        product_id=product.product_id if product else None,
        product_definition_version=product.definition_version if product else None,
        product_selection_source=product_selection_source if product else None,
        out_of_product_overrides=tuple(sorted(explicit_requested - product_ids)) if product else (),
    )


def apply_chargeable_scanner_gate(
    selection: ScannerSelection,
    *,
    allow_chargeable_scanners: bool,
    provider_id: str | None = None,
    provider_scanner_catalog: ProviderScannerCatalog | None = None,
) -> ScannerSelection:
    """Block selected scanners that can incur AWS charges unless explicitly allowed."""
    scanner_definitions = scanner_definitions_for_catalog(
        resolve_provider_scanner_catalog(
            provider_id=provider_id,
            provider_scanner_catalog=provider_scanner_catalog,
        ),
    )
    if allow_chargeable_scanners:
        return ScannerSelection(
            enabled_ids=selection.enabled_ids,
            disabled_ids=selection.disabled_ids,
            selected_pillars=selection.selected_pillars,
            pillar_filter_applied=selection.pillar_filter_applied,
            pillar_filter_bypass_reason=selection.pillar_filter_bypass_reason,
            pillar_policy_summary=dict(selection.pillar_policy_summary),
            disabled_reasons=dict(selection.disabled_reasons),
            product_id=selection.product_id,
            product_definition_version=selection.product_definition_version,
            product_selection_source=selection.product_selection_source,
            out_of_product_overrides=selection.out_of_product_overrides,
        )

    enabled = set(selection.enabled_ids)
    disabled = set(selection.disabled_ids)
    disabled_reasons = dict(selection.disabled_reasons)
    blocks = {block.scanner_id: block for block in selection.chargeable_blocks if block.scanner_id in disabled or block.scanner_id in enabled}
    for scanner_id in sorted(enabled):
        definition = scanner_definitions.get(scanner_id)
        if definition is None:
            continue
        if not definition.may_incur_charges:
            continue
        enabled.remove(scanner_id)
        disabled.add(scanner_id)
        disabled_reasons[scanner_id] = (
            "Scanner intentionally not run because chargeable scanners are "
            "disabled by default. "
            f"Enable {CHARGEABLE_SCANNER_CLI_OPTION} or "
            f"{CHARGEABLE_SCANNER_CONFIG_KEY} to run it. "
            f"Reason: {definition.chargeable_reason}"
        )
        blocks[scanner_id] = ChargeableScannerBlock(
            scanner_id=scanner_id,
            reason=definition.chargeable_reason or "This scanner can incur AWS charges during collection.",
        )

    return ScannerSelection(
        enabled_ids=tuple(sorted(enabled)),
        disabled_ids=tuple(sorted(disabled)),
        chargeable_blocks=tuple(blocks[key] for key in sorted(blocks)),
        selected_pillars=selection.selected_pillars,
        pillar_filter_applied=selection.pillar_filter_applied,
        pillar_filter_bypass_reason=selection.pillar_filter_bypass_reason,
        pillar_policy_summary=dict(selection.pillar_policy_summary),
        disabled_reasons={
            scanner_id: disabled_reasons.get(
                scanner_id,
                "Scanner disabled by final scanner selection.",
            )
            for scanner_id in sorted(disabled)
        },
        product_id=selection.product_id,
        product_definition_version=selection.product_definition_version,
        product_selection_source=selection.product_selection_source,
        out_of_product_overrides=selection.out_of_product_overrides,
    )


def build_chargeable_scanner_policy(  # noqa: D103
    selection: ScannerSelection,
    *,
    allow_chargeable_scanners: bool,
    provider_id: str | None = None,
    provider_scanner_catalog: ProviderScannerCatalog | None = None,
) -> dict[str, object]:
    scanner_definitions = scanner_definitions_for_catalog(
        resolve_provider_scanner_catalog(
            provider_id=provider_id,
            provider_scanner_catalog=provider_scanner_catalog,
        ),
    )
    chargeable_scanners = [scanner.convert_to_dict() for scanner in scanner_definitions.values() if scanner.may_incur_charges]
    return {
        "allow_chargeable_scanners": allow_chargeable_scanners,
        "default": False,
        "config_key": CHARGEABLE_SCANNER_CONFIG_KEY,
        "cli_option": CHARGEABLE_SCANNER_CLI_OPTION,
        "chargeable_scanners": chargeable_scanners,
        "blocked_scanners": [block.convert_to_dict() for block in selection.chargeable_blocks],
    }


def get_chargeable_block(  # noqa: D103
    selection: ScannerSelection,
    scanner_id: str,
) -> ChargeableScannerBlock | None:
    for block in selection.chargeable_blocks:
        if block.scanner_id == scanner_id:
            return block
    return None


def resolve_provider_scanner_catalog(
    *,
    provider_id: str | None,
    provider_scanner_catalog: ProviderScannerCatalog | None,
) -> ProviderScannerCatalog:
    """Return the supplied or runtime-backed provider scanner catalog."""
    if provider_scanner_catalog is not None:
        return provider_scanner_catalog
    create_runtime_provider = import_module(PROVIDER_SELECTION_MODULE).create_runtime_provider
    runtime = create_runtime_provider(provider_id)
    return cast("ProviderScannerCatalog", runtime.build_scanner_catalog())


def scanner_definitions_for_catalog(
    provider_scanner_catalog: ProviderScannerCatalog,
) -> dict[str, ScannerDefinition]:
    """Return scanner definitions scoped to one provider catalog."""
    catalog_ids = {capability.scanner_id for capability in provider_scanner_catalog.capabilities}
    definitions = {scanner_id: definition for scanner_id, definition in SCANNERS.items() if scanner_id in catalog_ids}
    definitions.update(
        {definition.scanner_id: definition for definition in provider_scanner_catalog.scanner_definitions if definition.scanner_id in catalog_ids},
    )
    return definitions


def scanner_definitions_for_provider(provider_id: str | None) -> dict[str, ScannerDefinition]:
    """Return scanner definitions scoped to the selected provider catalog."""
    return scanner_definitions_for_catalog(
        resolve_provider_scanner_catalog(
            provider_id=provider_id,
            provider_scanner_catalog=None,
        ),
    )


def _get_pillar_allowed_scanner_ids(
    provider_scanner_catalog: ProviderScannerCatalog,
    selected_pillars: tuple[str, ...],
    *,
    provider_id: str | None,
) -> set[str]:
    catalog_ids = {capability.scanner_id for capability in provider_scanner_catalog.capabilities}
    if not selected_pillars or set(selected_pillars) == set(SCAN_PILLAR_IDS):
        return catalog_ids

    resolved_provider_id = provider_id or provider_scanner_catalog.provider_id
    if resolved_provider_id == AWS_PROVIDER_ID:
        return set(DEFAULT_SCANNER_PILLAR_POLICY.get_matching_scanner_ids(selected_pillars)) & catalog_ids

    selected = set(selected_pillars)
    return {capability.scanner_id for capability in provider_scanner_catalog.capabilities if selected & set(capability.pillars)}


def _build_pillar_policy_summary(
    provider_scanner_catalog: ProviderScannerCatalog,
    selected_pillars: tuple[str, ...],
    *,
    provider_id: str | None,
    filter_applied: bool,
    bypass_reason: str,
) -> dict[str, Any]:
    resolved_provider_id = provider_id or provider_scanner_catalog.provider_id
    if resolved_provider_id == AWS_PROVIDER_ID:
        summary = DEFAULT_SCANNER_PILLAR_POLICY.build_summary(selected_pillars)
        summary.update(
            {
                "filter_applied": filter_applied,
                "bypass_reason": bypass_reason,
            },
        )
        return summary

    scanner_ids_by_pillar = {
        pillar: sorted(capability.scanner_id for capability in provider_scanner_catalog.capabilities if pillar in capability.pillars)
        for pillar in SCAN_PILLAR_IDS
    }
    all_pillars_selected = not selected_pillars or set(selected_pillars) == set(SCAN_PILLAR_IDS)
    return {
        "selected_pillars": list(SCAN_PILLAR_IDS if all_pillars_selected else selected_pillars),
        "all_pillars_selected": all_pillars_selected,
        "available_pillars": list(SCAN_PILLAR_IDS),
        "scanner_count_by_pillar": {pillar: len(scanner_ids_by_pillar[pillar]) for pillar in SCAN_PILLAR_IDS},
        "scanner_ids_by_pillar": scanner_ids_by_pillar,
        "filter_applied": filter_applied,
        "bypass_reason": bypass_reason,
    }


def _validate_provider_scanner_ids(
    scanner_ids: list[str] | tuple[str, ...] | set[str],
    *,
    available_ids: set[str],
    provider_id: str | None,
) -> None:
    unknown = sorted(set(scanner_ids) - available_ids)
    if unknown:
        msg = build_unknown_scanner_ids_message(
            unknown,
            provider_id=provider_id,
        )
        raise ValueError(msg)
