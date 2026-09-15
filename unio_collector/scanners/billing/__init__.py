from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.billing.alerts_and_budgets import BillingAlertsAndBudgetsScanner
    from unio_collector.scanners.billing.packs import BILLING_SCANNER_PACKS, BILLING_SCANNER_TYPES
    from unio_collector.scanners.cost_explorer.commitment.evidence import CommitmentReviewEvidence
    from unio_collector.scanners.cost_explorer.commitment.scanner import CommitmentAndPricingReviewScanner
    from unio_collector.scanners.free_tier.usage_review import FreeTierUsageReviewScanner, build_free_tier_evidence_records


_EXPORTS = {
    "BILLING_SCANNER_PACKS": ("unio_collector.scanners.billing.packs", "BILLING_SCANNER_PACKS"),
    "BILLING_SCANNER_TYPES": ("unio_collector.scanners.billing.packs", "BILLING_SCANNER_TYPES"),
    "BillingAlertsAndBudgetsScanner": ("unio_collector.scanners.billing.alerts_and_budgets", "BillingAlertsAndBudgetsScanner"),
    "CommitmentAndPricingReviewScanner": ("unio_collector.scanners.cost_explorer.commitment.scanner", "CommitmentAndPricingReviewScanner"),
    "CommitmentReviewEvidence": ("unio_collector.scanners.cost_explorer.commitment.evidence", "CommitmentReviewEvidence"),
    "FreeTierUsageReviewScanner": ("unio_collector.scanners.free_tier.usage_review", "FreeTierUsageReviewScanner"),
    "build_free_tier_evidence_records": ("unio_collector.scanners.free_tier.usage_review", "build_free_tier_evidence_records"),
}

__all__ = [
    "BILLING_SCANNER_PACKS",
    "BILLING_SCANNER_TYPES",
    "BillingAlertsAndBudgetsScanner",
    "CommitmentAndPricingReviewScanner",
    "CommitmentReviewEvidence",
    "FreeTierUsageReviewScanner",
    "build_free_tier_evidence_records",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    if name not in _EXPORTS:
        raise AttributeError(name)
    module_name, symbol_name = _EXPORTS[name]
    symbol = getattr(import_module(module_name), symbol_name)
    globals()[name] = symbol
    return symbol
