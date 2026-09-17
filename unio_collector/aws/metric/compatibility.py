"""Lazy resolution of historical application-only metric helper exports."""

from importlib import import_module
from typing import Any

_EXPORTS = {
    "build_metric_summary": "unio_collector.analyzers.metric.compatibility",
    "interpret_metric_average": "unio_collector.analyzers.metric.policy",
}


def resolve_metric_export(name: str) -> Any:  # noqa: ANN401
    """Resolve an explicitly requested helper without embedding private policy."""
    if name not in _EXPORTS:
        raise AttributeError(name)
    return getattr(import_module(_EXPORTS[name]), name)
