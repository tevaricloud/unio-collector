from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field

from unio_collector.commitments.observation import ObservedCommitmentPortfolio  # noqa: TC001


@dataclass(frozen=True)
class CommitmentReviewEvidence:  # noqa: D101
    evidence_schema_version: str = "2026-08"
    account_id: str = "unknown-account"
    pricing_provider: str = "aws-native-cost-explorer"
    savings_plans_utilization: list[object] = field(default_factory=list)
    reservation_utilization: list[object] = field(default_factory=list)
    savings_plans_utilization_error: str | None = None
    reservation_utilization_error: str | None = None
    portfolio: ObservedCommitmentPortfolio | None = None

    def convert_to_signals(self) -> dict[str, object]:  # noqa: D102
        signals: dict[str, object] = {
            "pricing_provider": self.pricing_provider,
            "savings_plans_utilization": self.savings_plans_utilization,
            "reservation_utilization": self.reservation_utilization,
        }
        if self.savings_plans_utilization_error:
            signals["savings_plans_utilization_error"] = self.savings_plans_utilization_error
        if self.reservation_utilization_error:
            signals["reservation_utilization_error"] = self.reservation_utilization_error
        if self.portfolio is not None:
            signals["commitment_portfolio"] = self.portfolio.convert_to_dict()
        return signals
