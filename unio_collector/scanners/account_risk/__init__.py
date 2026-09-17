from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.account_risk.cost.evidence import AccountCostRiskEvidence
    from unio_collector.scanners.account_risk.cost.signal import AccountCostRiskSignalScanner
    from unio_collector.scanners.account_risk.packs import ACCOUNT_RISK_SCANNER_MODULE_REGISTRATION, ACCOUNT_RISK_SCANNER_PACKS, ACCOUNT_RISK_SCANNER_TYPES
    from unio_collector.scanners.account_risk.root.recovery.scanner import RootAccountRecoveryAdvisoryScanner

_EXPORTS = {
    "ACCOUNT_RISK_SCANNER_MODULE_REGISTRATION": ("unio_collector.scanners.account_risk.packs", "ACCOUNT_RISK_SCANNER_MODULE_REGISTRATION"),
    "ACCOUNT_RISK_SCANNER_PACKS": ("unio_collector.scanners.account_risk.packs", "ACCOUNT_RISK_SCANNER_PACKS"),
    "ACCOUNT_RISK_SCANNER_TYPES": ("unio_collector.scanners.account_risk.packs", "ACCOUNT_RISK_SCANNER_TYPES"),
    "AccountCostRiskEvidence": ("unio_collector.scanners.account_risk.cost.evidence", "AccountCostRiskEvidence"),
    "AccountCostRiskSignalScanner": ("unio_collector.scanners.account_risk.cost.signal", "AccountCostRiskSignalScanner"),
    "RootAccountRecoveryAdvisoryScanner": ("unio_collector.scanners.account_risk.root.recovery.scanner", "RootAccountRecoveryAdvisoryScanner"),
}

__all__ = [
    "ACCOUNT_RISK_SCANNER_MODULE_REGISTRATION",
    "ACCOUNT_RISK_SCANNER_PACKS",
    "ACCOUNT_RISK_SCANNER_TYPES",
    "AccountCostRiskEvidence",
    "AccountCostRiskSignalScanner",
    "RootAccountRecoveryAdvisoryScanner",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve retained public exports without importing private analysis eagerly."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
