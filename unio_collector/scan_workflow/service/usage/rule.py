from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceUsagePrecheckRule:
    """Billing-service pattern rule for deciding scanner execution."""

    service_patterns: tuple[str, ...]
    require_billing_match_to_run: bool = True
    no_spend_run_reason: str = (
        "This metadata scanner can still provide useful evidence when Cost Explorer shows no matching service spend in the selected scan window."
    )
