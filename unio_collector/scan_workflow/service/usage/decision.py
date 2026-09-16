from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceUsagePrecheckDecision:
    """Decision from service-usage precheck policy."""

    scanner_id: str
    should_run: bool
    reason: str
    matched_services: tuple[str, ...] = ()
    configured_service_patterns: tuple[str, ...] = ()
    precheck_mode: str = "billing_match_required"
    billing_match_required_to_run: bool = True

    def convert_to_coverage_note(self) -> dict[str, object]:
        """Return this precheck decision as a scanner coverage note."""
        if self.should_run:
            impact = (
                "This scanner ran because the service-usage precheck did not "
                "require a matching Cost Explorer service line before "
                "collecting read-only metadata."
            )
        else:
            impact = (
                "This scanner made no service-specific AWS API calls because "
                "Cost Explorer did not show matching service spend in the "
                "selected scan window. Use --force-service-scanners to run it "
                "anyway for development or verification."
            )
        return {
            "note_type": "service_usage_precheck",
            "summary": self.reason,
            "matched_services": list(self.matched_services),
            "configured_service_patterns": list(self.configured_service_patterns),
            "precheck_mode": self.precheck_mode,
            "billing_match_required_to_run": self.billing_match_required_to_run,
            "result_scope": "current_scan_period",
            "impact": impact,
        }
