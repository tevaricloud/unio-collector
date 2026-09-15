from __future__ import annotations  # noqa: D100

from importlib import import_module
from typing import TYPE_CHECKING, cast

from unio_collector.scanners.collection.class_paths import COLLECTOR_SCANNER_CLASS_PATHS

if TYPE_CHECKING:
    from unio_collector.scanners.base import BaseUnioScanner
    from unio_collector.scanners.scanner.definition import ScannerDefinition


def build_collector_scanner(
    scanner_id: str,
    definition: ScannerDefinition,
) -> BaseUnioScanner:
    """Build one scanner lazily from collector metadata."""
    try:
        factory_path = COLLECTOR_SCANNER_CLASS_PATHS[scanner_id]
    except KeyError as exc:
        msg = f"No collector factory registered for scanner: {scanner_id}"
        raise ValueError(msg) from exc
    module_name, _, attribute_name = factory_path.partition(":")
    if not module_name or not attribute_name:
        msg = f"Invalid collector factory path for scanner {scanner_id}: {factory_path}"
        raise ValueError(msg)
    scanner_type = getattr(import_module(module_name), attribute_name)
    return cast("type[BaseUnioScanner]", scanner_type)(definition)
