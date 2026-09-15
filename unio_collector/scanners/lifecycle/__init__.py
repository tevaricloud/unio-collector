from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.lifecycle.eol_scanner import ExtendedSupportAndEolReviewScanner
    from unio_collector.scanners.lifecycle.packs import LIFECYCLE_SCANNER_PACKS, LIFECYCLE_SCANNER_TYPES

_EXPORTS = {
    "LIFECYCLE_SCANNER_PACKS": ("unio_collector.scanners.lifecycle.packs", "LIFECYCLE_SCANNER_PACKS"),
    "LIFECYCLE_SCANNER_TYPES": ("unio_collector.scanners.lifecycle.packs", "LIFECYCLE_SCANNER_TYPES"),
    "ExtendedSupportAndEolReviewScanner": ("unio_collector.scanners.lifecycle.eol_scanner", "ExtendedSupportAndEolReviewScanner"),
}

__all__ = ["LIFECYCLE_SCANNER_PACKS", "LIFECYCLE_SCANNER_TYPES", "ExtendedSupportAndEolReviewScanner"]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve retained public exports without importing private analysis eagerly."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
