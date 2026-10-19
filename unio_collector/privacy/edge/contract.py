"""Exact registered CloudFront contracts; arbitrary provider strings remain protected."""

from dataclasses import replace
from math import isfinite
from typing import Any

from unio_collector.privacy.audit.contract import AuditPrivacyContract
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.edge.coverage import EdgeCoverageContract
from unio_collector.privacy.edge.regional import EdgeRegionalCoverageContract
from unio_collector.privacy.edge.scan import EdgeScanAdmission
from unio_collector.privacy.edge.vocabulary import ALB_LITERALS, PRESERVED
from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

MAX_PORT = 65535
HISTOGRAM_SIZE = 64


class EdgePrivacyContract(AuditPrivacyContract):
    """Share typed port/histogram validation without accepting undeclared descendants."""

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        if value is None:
            return nullable
        if kind == "port":
            return type(value) is int and -1 <= value <= MAX_PORT
        if kind == "number":
            return isinstance(value, int | float) and not isinstance(value, bool) and isfinite(value) and value >= 0
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: object, member: str, suffix: str = "") -> list[str]:
        """Retain the producer's fixed 64-bin bounded histogram, including malformed negatives."""
        failures = super().unknown_paths(value, member, suffix)
        if (
            suffix == "records[].behavior_histogram.counts"
            and isinstance(value, list)
            and (len(value) != HISTOGRAM_SIZE or any(type(child) is not int or not 0 <= child < 2**63 for child in value) or sum(value) >= 2**63)
        ):
            failures.append(member + self.prefix[1:] + "." + suffix)
        if (
            self.scanner_id == "cloudfront-alb-origin-protection-review"
            and suffix in ALB_LITERALS
            and (not isinstance(value, str) or value not in ALB_LITERALS[suffix])
        ):
            failures.append(member + self.prefix[1:] + "." + suffix)
        return failures

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect CIDRs in both profiles, retaining the declared semantic category."""
        decision = super().resolve(path, profile)
        return replace(decision, treatment="tokenise") if decision is not None and decision.category == "cidr" else decision

    def admitted_scan_container(self, value: object, suffix: str) -> bool:
        """Accept only the existing strict timestamp representation in this scan-only copy."""
        return EdgeScanAdmission.check(self, value, suffix)

    def for_container(self, value: dict[str, Any], path: str) -> ClosedProducerContract | None:
        """Bind coverage scope semantics only inside this validated registered ALB producer."""
        if (
            self.scanner_id == "cloudfront-alb-origin-protection-review"
            and path == self.prefix + ".coverage[]"
            and not self.unknown_paths(value, "", "coverage[]")
        ):
            owner = EdgeRegionalCoverageContract if value.get("evidence_type") == "managed_prefix_lists" else EdgeCoverageContract
            return owner(value.get("evidence_type"), value.get("status"))
        return None

    def is_literal(self, suffix: str, value: object) -> bool:
        """Mask only finite controls at exact roles; arbitrary customer positions still scan."""
        choices = {**ALB_LITERALS, **PRESERVED} if self.scanner_id == "cloudfront-alb-origin-protection-review" else PRESERVED
        return suffix in self.fields and isinstance(value, str) and value in choices.get(suffix, ())

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Preserve recognized metadata; protect arbitrary provider text in the same positions."""
        decision = self.resolve(path, profile)
        return (
            replace(decision, category="safe_metadata", treatment="preserve")
            if decision is not None and self.is_literal(path.removeprefix(self.prefix + "."), value)
            else decision
        )
