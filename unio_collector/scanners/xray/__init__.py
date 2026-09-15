from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.xray.collector import build_xray_collector
    from unio_collector.scanners.xray.cost_evidence import XRayCostGovernanceEvidence
    from unio_collector.scanners.xray.packs import XRAY_SCANNER_MODULE_REGISTRATION, XRAY_SCANNER_PACKS, XRAY_SCANNER_TYPES
    from unio_collector.scanners.xray.tracing_scanner import XRayTracingCostGovernanceReviewScanner


_EXPORTS = {
    "XRAY_SCANNER_MODULE_REGISTRATION": ("unio_collector.scanners.xray.packs", "XRAY_SCANNER_MODULE_REGISTRATION"),
    "XRAY_SCANNER_PACKS": ("unio_collector.scanners.xray.packs", "XRAY_SCANNER_PACKS"),
    "XRAY_SCANNER_TYPES": ("unio_collector.scanners.xray.packs", "XRAY_SCANNER_TYPES"),
    "XRayCostGovernanceEvidence": ("unio_collector.scanners.xray.cost_evidence", "XRayCostGovernanceEvidence"),
    "XRayTracingCostGovernanceReviewScanner": ("unio_collector.scanners.xray.tracing_scanner", "XRayTracingCostGovernanceReviewScanner"),
    "build_xray_collector": ("unio_collector.scanners.xray.collector", "build_xray_collector"),
}

__all__ = [
    "XRAY_SCANNER_MODULE_REGISTRATION",
    "XRAY_SCANNER_PACKS",
    "XRAY_SCANNER_TYPES",
    "XRayCostGovernanceEvidence",
    "XRayTracingCostGovernanceReviewScanner",
    "build_xray_collector",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    if name not in _EXPORTS:
        raise AttributeError(name)
    module_name, symbol_name = _EXPORTS[name]
    symbol = getattr(import_module(module_name), symbol_name)
    globals()[name] = symbol
    return symbol
