"""Closed execution-detail notes emitted by seven explicitly audited wrappers."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any, ClassVar, Self

from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.s3.fields import fields

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

DETAIL_COUNTS = {
    "kms-cost-governance-review": {
        "listed_key_count",
        "key_count",
        "customer_managed_key_count",
        "multi_region_key_count",
        "disabled_customer_key_count",
        "alias_count",
    },
    "config-cost-governance-review": {"recorder_count", "all_supported_recording_count", "config_rule_count", "conformance_pack_count"},
    "guardduty-cost-governance-review": {"detector_count", "enabled_feature_count", "disabled_feature_count"},
    "securityhub-inspector-macie-cost-review": {"securityhub_standard_count", "inspector_enabled", "macie_enabled", "macie_classification_job_count"},
    "waf-cost-governance-review": {"web_acl_count", "managed_rule_group_count", "rate_based_rule_count", "associated_resource_count"},
    "cloudtrail-cost-governance-review": {"trail_count", "data_event_selector_count", "insight_selector_count", "event_data_store_count"},
    "secrets-manager-cost-governance-review": {
        "secret_count",
        "active_secret_count",
        "rotation_disabled_secret_count",
        "missing_last_access_secret_count",
        "replica_secret_count",
    },
}
RESOURCE_LABELS = {
    "kms-cost-governance-review": "key or alias",
    "cloudtrail-cost-governance-review": "trail or event data store",
    "secrets-manager-cost-governance-review": "secret",
    "config-cost-governance-review": "recorder, rule, or conformance pack",
    "guardduty-cost-governance-review": "detector or protection feature",
    "securityhub-inspector-macie-cost-review": "security-service control",
    "waf-cost-governance-review": "web ACL or managed rule group",
}
LITERALS = {
    "note_type": {"execution_detail"},
    "scope_area": {"audit_service_metadata"},
    "result_scope": {"metadata_with_optional_billing_context"},
    "resource_label": {
        "trail or event data store",
        "key or alias",
        "secret",
        "recorder, rule, or conformance pack",
        "detector or protection feature",
        "security-service control",
        "web ACL or managed rule group",
    },
    "scanner_id": set(DETAIL_COUNTS),
}
NOTE_FIELDS = {
    "": ("object", "safe_metadata", False),
    **fields("detail_counts", "object"),
    **fields("association_detail_modes", "array"),
    **fields("association_detail_modes[]", "association_mode"),
    **fields("association_metadata_collected_record_count association_metadata_skipped_record_count", "count", "summary_count"),
    **fields("note_type scope_area result_scope resource_label scanner_id", "note_literal"),
    **fields("summary impact", "string", "free_text"),
    **fields("regions_attempted", "array"),
    **fields("regions_attempted[]", "string", "region"),
    **fields("region_record_count resource_count billing_context_record_count permission_error_count", "count", "summary_count"),
    **fields(" ".join("detail_counts." + name for name in sorted(set.union(*DETAIL_COUNTS.values()))), "count", "summary_count"),
}


class AuditNoteContract(ClosedProducerContract):
    """Admit one finite producer note, preserving count meaning and protecting prose."""

    prefix: ClassVar[str] = "$.scanner_results[].coverage_notes[]"
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = NOTE_FIELDS

    def __init__(self, scanner: str) -> None:
        """Bind conditional count keys to the originating scanner."""
        self.scanner = scanner

    @classmethod
    def for_note(cls, value: dict[str, Any]) -> Self | None:
        """Bind exact scanner IDs before validating the note kind; no discriminant bypass."""
        scanner = value.get("scanner_id")
        if not isinstance(scanner, str) or scanner not in DETAIL_COUNTS:
            return None
        return cls(scanner)

    def unknown_record_paths(self, record: dict[str, Any], member: str) -> list[str]:
        """Validate the note itself rather than an evidence envelope."""
        return self.unknown_paths(record, member)

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Reject wrong-scanner counters and invalid enum values before omission."""
        failures = super().unknown_paths(value, member, suffix)
        if suffix == "detail_counts" and isinstance(value, dict):
            failures.extend(member + self.prefix[1:] + ".detail_counts." + key for key in value if key not in DETAIL_COUNTS[self.scanner])
        if suffix.startswith(("association_detail_modes", "association_metadata_")) and self.scanner != "waf-cost-governance-review":
            failures.append(member + self.prefix[1:] + "." + suffix)
        if suffix == "resource_label" and value != RESOURCE_LABELS[self.scanner]:
            failures.append(member + self.prefix[1:] + ".resource_label")
        if suffix in LITERALS and (not isinstance(value, str) or value not in LITERALS[suffix]):
            failures.append(member + self.prefix[1:] + "." + suffix)
        return failures

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Only strings reach per-position literal validation."""
        if kind == "association_mode":
            return isinstance(value, str) and value in {"full", "summary"}
        if kind == "note_literal":
            return isinstance(value, str)
        return super()._valid(value, kind, nullable=nullable)

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect entire arbitrary explanatory strings, without leaking evidence values."""
        decision = super().resolve(path, profile)
        return replace(decision, treatment="tokenise") if decision is not None and decision.category == "free_text" else decision

    def is_literal(self, suffix: str, value: str) -> bool:
        """Recognize only this admitted note's exact fixed metadata positions."""
        if suffix == "resource_label":
            return value == RESOURCE_LABELS[self.scanner]
        if suffix == "scanner_id":
            return value == self.scanner
        return (suffix in LITERALS and value in LITERALS[suffix]) or (suffix == "association_detail_modes[]" and value in {"full", "summary"})
