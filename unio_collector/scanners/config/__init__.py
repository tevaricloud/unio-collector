from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.cloudwatch.log_retention.scanner import CloudWatchLogRetentionScanner

_EXPORTS = {"CloudWatchLogRetentionScanner": ("unio_collector.scanners.cloudwatch.log_retention.scanner", "CloudWatchLogRetentionScanner")}

__all__ = ["CloudWatchLogRetentionScanner"]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value
