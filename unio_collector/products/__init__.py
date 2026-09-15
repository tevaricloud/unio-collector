"""Lazy compatibility exports for full product execution contracts."""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORTS: dict[str, tuple[str, str]] = {
    "PRODUCT_REGISTRY": (
        "unio_collector.products.registry",
        "PRODUCT_REGISTRY",
    ),
    "PRODUCT_REGISTRY_VERSION": (
        "unio_collector.products.registry",
        "PRODUCT_REGISTRY_VERSION",
    ),
    "ProductDefinition": (
        "unio_collector.products.contracts.definition",
        "ProductDefinition",
    ),
    "ProductId": ("unio_collector.products.collection", "ProductId"),
    "ProductRegistry": ("unio_collector.products.registry", "ProductRegistry"),
}

__all__ = [
    "PRODUCT_REGISTRY",
    "PRODUCT_REGISTRY_VERSION",
    "ProductDefinition",
    "ProductId",
    "ProductRegistry",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve a historical product export from its canonical module."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
