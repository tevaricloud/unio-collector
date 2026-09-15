from __future__ import annotations  # noqa: D104

# pyright: reportUnsupportedDunderAll=false
from importlib import import_module
from typing import Any

_EXPORTS = {
    "VpcFlowLogAttributionEvidence": (
        "unio_collector.scanners.network.vpc_flow.attribution.evidence",
        "VpcFlowLogAttributionEvidence",
    ),
    "VpcFlowLogAttributionScanner": (
        "unio_collector.scanners.network.vpc_flow.attribution.scanner",
        "VpcFlowLogAttributionScanner",
    ),
}

__all__ = (
    "VpcFlowLogAttributionEvidence",
    "VpcFlowLogAttributionScanner",
)


def __getattr__(name: str) -> Any:  # noqa: ANN401
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    module = import_module(module_name)
    return getattr(module, attribute_name)
