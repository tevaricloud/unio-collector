"""Resolve explicitly requested application allowance helpers lazily."""

from importlib import import_module
from typing import Any

_EXPORTS = {
    "select_threshold_usage_records": "unio_collector.analyzers.allowance.selection",
    "build_free_tier_limitations": "unio_collector.analyzers.allowance.messages",
    "build_free_tier_visibility_messages": "unio_collector.analyzers.allowance.messages",
    "build_free_tier_summary": "unio_collector.analyzers.allowance.summary",
    "build_free_tier_scanner_warnings": "unio_collector.analyzers.allowance.summary",
}


def resolve_free_tier_export(name: str) -> Any:  # noqa: ANN401
    """Load an application helper without importing it during collection."""
    if name not in _EXPORTS:
        raise AttributeError(name)
    return getattr(import_module(_EXPORTS[name]), name)
