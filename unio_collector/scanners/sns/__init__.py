from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.sns.cost_governance import SnsCostGovernanceReviewScanner


_EXPORTS = {
    "SnsCostGovernanceReviewScanner": ("unio_collector.scanners.sns.cost_governance", "SnsCostGovernanceReviewScanner"),
}

__all__ = ["SnsCostGovernanceReviewScanner"]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    if name not in _EXPORTS:
        raise AttributeError(name)
    module_name, symbol_name = _EXPORTS[name]
    symbol = getattr(import_module(module_name), symbol_name)
    globals()[name] = symbol
    return symbol
