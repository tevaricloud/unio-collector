from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class PricingEnrichmentStatus:  # noqa: D101
    raw_status: str
    stop_reason: str | None
    completion_state: str
    display_status: str
    explanation: str
    bounded_budget_reached: bool = False
    expected_partial_result: bool = False

    def convert_to_dict(self) -> dict[str, object]:  # noqa: D102
        return {
            "raw_status": self.raw_status,
            "stop_reason": self.stop_reason,
            "completion_state": self.completion_state,
            "display_status": self.display_status,
            "explanation": self.explanation,
            "bounded_budget_reached": self.bounded_budget_reached,
            "expected_partial_result": self.expected_partial_result,
        }
