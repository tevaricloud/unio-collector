from __future__ import annotations  # noqa: D100

from importlib import import_module
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from unio_collector.scanners.base import BaseUnioScanner
    from unio_collector.scanners.scanner.definition import ScannerDefinition


def build_scanner_from_collector_factory_path(
    scanner_id: str,
    definition: ScannerDefinition,
) -> BaseUnioScanner:
    """Resolve the scanner's collector factory path lazily."""
    module_name, _, attribute_name = definition.collector_factory_path.partition(":")
    if not module_name or not attribute_name:
        msg = f"Invalid collector factory path for scanner {scanner_id}: {definition.collector_factory_path}"
        raise ValueError(msg)
    factory = getattr(import_module(module_name), attribute_name)
    return cast("BaseUnioScanner", factory(scanner_id, definition))
