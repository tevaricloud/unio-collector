from __future__ import annotations  # noqa: D104

# pyright: reportUnsupportedDunderAll=false
from importlib import import_module
from typing import Any

_EXPORTS = {
    "DATA_TRANSFER_SCANNER_MODULE_REGISTRATION": ("unio_collector.scanners.data_transfer.packs", "DATA_TRANSFER_SCANNER_MODULE_REGISTRATION"),
    "DATA_TRANSFER_SCANNER_PACKS": ("unio_collector.scanners.data_transfer.packs", "DATA_TRANSFER_SCANNER_PACKS"),
    "DATA_TRANSFER_SCANNER_TYPES": ("unio_collector.scanners.data_transfer.packs", "DATA_TRANSFER_SCANNER_TYPES"),
    "DataTransferCostReviewScanner": ("unio_collector.scanners.data_transfer.cost_scanner", "DataTransferCostReviewScanner"),
    "NatGatewayCostEvidence": ("unio_collector.scanners.network.nat_gateway.evidence", "NatGatewayCostEvidence"),
    "NatGatewayCostReviewScanner": ("unio_collector.scanners.network.nat_gateway.scanner", "NatGatewayCostReviewScanner"),
}

__all__ = (
    "DATA_TRANSFER_SCANNER_MODULE_REGISTRATION",
    "DATA_TRANSFER_SCANNER_PACKS",
    "DATA_TRANSFER_SCANNER_TYPES",
    "DataTransferCostReviewScanner",
    "NatGatewayCostEvidence",
    "NatGatewayCostReviewScanner",
)


def __getattr__(name: str) -> Any:  # noqa: ANN401
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
