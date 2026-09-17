"""Resolve historical analytics option imports only when explicitly requested."""

from importlib import import_module
from typing import Any

_EXPORTS = {
    "AthenaQueryExecutionCollectionOptions": "unio_collector.analyzers.analytics.options.athena",
    "GlueJobRunCollectionOptions": "unio_collector.analyzers.analytics.options.glue",
}


def resolve_analytics_export(name: str) -> Any:  # noqa: ANN401
    """Load application defaults without making them collection dependencies."""
    if name not in _EXPORTS:
        raise AttributeError(name)
    return getattr(import_module(_EXPORTS[name]), name)
