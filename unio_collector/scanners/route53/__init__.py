from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.route53.cost_governance import Route53CostGovernanceReviewScanner


_EXPORTS = {
    "Route53CostGovernanceReviewScanner": ("unio_collector.scanners.route53.cost_governance", "Route53CostGovernanceReviewScanner"),
}

__all__ = ["Route53CostGovernanceReviewScanner"]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    if name not in _EXPORTS:
        raise AttributeError(name)
    module_name, symbol_name = _EXPORTS[name]
    symbol = getattr(import_module(module_name), symbol_name)
    globals()[name] = symbol
    return symbol
