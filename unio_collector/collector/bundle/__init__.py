from __future__ import annotations  # noqa: D104

# pyright: reportUnsupportedDunderAll=false
from importlib import import_module
from typing import Any

_EXPORTS = {
    "BundleWriteResult": (
        "unio_collector.collector.bundle.write_result",
        "BundleWriteResult",
    ),
    "EvidenceBundleReadResult": (
        "unio_collector.collector.bundle.read_result",
        "EvidenceBundleReadResult",
    ),
    "EvidenceBundleReader": (
        "unio_collector.collector.bundle.reader",
        "EvidenceBundleReader",
    ),
    "EvidenceBundleValidator": (
        "unio_collector.collector.bundle.validator",
        "EvidenceBundleValidator",
    ),
    "EvidenceBundleWriter": (
        "unio_collector.collector.bundle.writer",
        "EvidenceBundleWriter",
    ),
}

__all__ = tuple(_EXPORTS)


def __getattr__(name: str) -> Any:  # noqa: ANN401
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    module = import_module(module_name)
    return getattr(module, attribute_name)
