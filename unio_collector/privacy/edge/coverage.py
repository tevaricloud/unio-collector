"""Bind the mixed coverage scope to its actual collection discriminator."""

from dataclasses import replace
from typing import ClassVar

from unio_collector.privacy.audit.contract import AuditPrivacyContract
from unio_collector.privacy.edge.fields import ALB
from unio_collector.privacy.edge.vocabulary import ALB_LITERALS
from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision


class EdgeCoverageContract(AuditPrivacyContract):
    """A generated global scope is distinct from a customer identifier named global."""

    fields: ClassVar = {path: spec for path, spec in ALB.items() if path.startswith("coverage[]")}

    def __init__(self, evidence_type: object, status: object) -> None:
        """Retain one container's discriminator without pooling neighboring rows."""
        self.evidence_type = evidence_type
        self.status = status

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Only the generated global collection scope is a literal, never a VPC-origin identity."""
        decision = super().resolve_string(path, value, profile)
        if decision is not None and self.is_literal(path.removeprefix(self.prefix + "."), value):
            return replace(decision, category="safe_metadata", treatment="preserve")
        if path == self.prefix + ".coverage[].scope_id" and decision is not None and self.evidence_type == "managed_prefix_lists":
            return replace(decision, category="region", treatment="generalise" if profile == "strict" else "profile_configurable")
        return decision

    def is_literal(self, suffix: str, value: object) -> bool:
        """Recognize global only at the actual collection coverage role."""
        if suffix in ALB_LITERALS and isinstance(value, str):
            return value in ALB_LITERALS[suffix]
        generated_global = self.evidence_type == "cloudfront_origins" or (self.evidence_type == "vpc_origin_detail" and self.status == "not_applicable")
        return suffix == "coverage[].scope_id" and generated_global and value == "global"
