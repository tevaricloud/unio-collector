"""Closed financial/text contract for the actual AWS Free Tier DTOs."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.s3.fields import fields
from unio_collector.scanners.scanner.schema import admit_evidence_schema

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision
VOCABULARIES = {"plan_type": {"FREE", "PAID"}, "plan_status": {"NOT_STARTED", "ACTIVE", "EXPIRED"}}
FIELDS = {
    "": ("object", "safe_metadata", False),
    **fields("account_id", "string", "aws_account_id"),
    **fields("account_plan.account_id", "string", "aws_account_id", nullable=True),
    **fields("account_plan", "object", nullable=True),
    **fields("usage_records permission_errors api_errors", "array"),
    **fields("usage_records[]", "object"),
    **fields("page_count", "count", "summary_count"),
    **fields("account_plan.account_plan_type", "plan_type", nullable=True),
    **fields("account_plan.account_plan_status", "plan_status", nullable=True),
    **fields(
        "account_plan.remaining_credit_amount usage_records[].actual_usage_amount usage_records[].forecasted_usage_amount usage_records[].limit",
        "decimal",
        "cost",
        nullable=True,
    ),
    **fields("account_plan.remaining_credit_unit", "string", "cost", nullable=True),
    **fields("account_plan.expiration_date", "timestamp", "timestamp", nullable=True),
    **fields("usage_records[].service usage_records[].operation usage_records[].usage_type usage_records[].free_tier_type", "string", "resource_name"),
    **fields("usage_records[].unit", "string", "cost"),
    **fields("usage_records[].description permission_errors[] api_errors[]", "string", "free_text"),
    **fields("usage_records[].region", "string", "region"),
}

REQUIRED = {
    "": {"account_id", "account_plan", "usage_records", "page_count", "permission_errors", "api_errors"},
    "account_plan": {"account_id", "account_plan_type", "account_plan_status", "remaining_credit_amount", "remaining_credit_unit", "expiration_date"},
    "usage_records[]": {
        "service",
        "operation",
        "usage_type",
        "region",
        "actual_usage_amount",
        "forecasted_usage_amount",
        "limit",
        "unit",
        "description",
        "free_tier_type",
    },
}


PUBLIC_BILLING_REFERENCES = frozenset(
    {
        ("Amazon S3", "TimedStorage-ByteHrs", "TimedStorage-ByteHrs", "GB-Mo"),
        ("Amazon S3", "TimedStorage-ByteHrs", "TimedStorage-ByteHrs", ""),
        ("Amazon Simple Storage Service", "Requests-Tier1", "Requests-Tier1", "Requests"),
    }
)


class FreeTierPrivacyContract(ClosedProducerContract):
    """Admit only the registered AWS result; arbitrary provider prose protects."""

    scanner_id: ClassVar[str] = "free-tier-usage-review"
    fields: ClassVar = FIELDS

    def __init__(self, *, usage_scope: bool = False, billing_fields: tuple[tuple[str, str], ...] = ()) -> None:
        """Keep row-qualified public references immutable and local to one traversal."""
        self._usage_scope = usage_scope
        self._billing_fields = billing_fields

    def for_container(self, value: dict[str, Any], path: str) -> FreeTierPrivacyContract | None:
        """Bind only complete, typed, exact provider billing-reference tuples."""
        if self._usage_scope or path != self.prefix + ".usage_records[]":
            return None
        reference = tuple(value.get(key) for key in ("service", "operation", "usage_type", "unit"))
        admitted = not self.unknown_paths(value, "", "usage_records[]") and reference in PUBLIC_BILLING_REFERENCES
        billing = tuple((key, value[key]) for key in ("service", "operation", "usage_type", "unit")) if admitted else ()
        return type(self)(usage_scope=True, billing_fields=billing)

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Preserve qualified standard billing references without a scan exemption."""
        decision = self.resolve(path, profile)
        field = path.removeprefix(self.prefix + ".usage_records[].")
        if decision is not None and profile == "standard" and (field, value) in self._billing_fields:
            return replace(
                decision,
                treatment="preserve",
                category="cost" if field == "unit" else "safe_metadata",
                reason="Exact typed provider billing reference; raw and known-original leak scanning remain unchanged.",
            )
        return decision

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Admit exact result identities before any field treatment."""
        if record.get("scanner_id") != cls.scanner_id:
            return None
        identities = {(f"{namespace}.aws.free_tier.collection_result", "FreeTierCollectionResult") for namespace in UNIO_PROTOCOL.accepted_import_namespaces}
        if (
            admit_evidence_schema(record) is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type")) not in identities
            or record.get("serialization_status") != "serialized"
            or record.get("serialization_format") != "json-compatible-python-object"
        ):
            message = "Free Tier privacy requires its matching registered AWS DTO identity."
            raise ValueError(message)
        return cls()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Keep finite SDK controls, nullable dates and financial decimals typed."""
        if value is None:
            return nullable
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        if kind == "decimal":
            if not isinstance(value, str):
                return False
            try:
                return Decimal(value).is_finite()
            except InvalidOperation:
                return False
        if kind == "timestamp":
            if not isinstance(value, str):
                return False
            try:
                datetime.fromisoformat(value)
            except ValueError:
                return False
            return True
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: object, member: str, suffix: str = "") -> list[str]:
        """Require all canonical DTO fields while rejecting unknown descendants."""
        failures = super().unknown_paths(value, member, suffix)
        if isinstance(value, dict) and suffix in REQUIRED:
            failures.extend(member + self.prefix[1:] + ("." + suffix if suffix else "") + "." + key for key in sorted(REQUIRED[suffix] - value.keys()))
        return failures

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect arbitrary text and units, and retain strict financial removal."""
        decision = super().resolve(path, profile)
        if decision is not None and decision.category == "free_text":
            return replace(decision, treatment="tokenise")
        if (
            decision is not None
            and profile == "standard"
            and path in {self.prefix + ".account_plan.remaining_credit_unit", self.prefix + ".usage_records[].unit"}
        ):
            return replace(
                decision, category="resource_name", treatment="tokenise", reason="Unconstrained provider units protect as text; strict financial units remove."
            )
        return decision

    def is_literal(self, suffix: str, value: str) -> bool:
        """Recognize only the two independently declared SDK control vocabularies."""
        spec = self.fields.get(suffix)
        return spec is not None and spec[0] in VOCABULARIES and self._valid(value, spec[0], nullable=spec[2])
