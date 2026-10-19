"""Closed original Cost Explorer service-delta financial evidence contract."""

from __future__ import annotations

from dataclasses import replace
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.s3.fields import fields
from unio_collector.scanners.scanner.schema import admit_evidence_schema

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

PUBLIC_SERVICES = frozenset({"Amazon Simple Storage Service", "Amazon Elastic Compute Cloud - Compute", "Amazon S3", "Amazon EC2"})
PUBLIC_CURRENCIES = frozenset({"USD", "EUR", "GBP"})
FIELDS = {
    **fields(" result result.previous_period result.current_period", "object"),
    **fields("result.service_costs", "array"),
    **fields("result.service_costs[]", "object"),
    **fields(
        "absolute_threshold percent_threshold result.previous_period.total_cost result.current_period.total_cost",
        "decimal",
        "cost",
    ),
    **fields("result.service_costs[].previous_cost result.service_costs[].current_cost", "financial_number", "cost"),
    **fields(
        "result.previous_period.start_date result.previous_period.end_date result.current_period.start_date result.current_period.end_date", "date", "timestamp"
    ),
    **fields("result.previous_period.currency result.current_period.currency result.service_costs[].currency", "string", "cost"),
    **fields("result.service_costs[].service_name", "string", "resource_name"),
    **fields("result.service_costs[].region", "string", "region"),
    **fields("analysis_inputs_version", "version", "safe_metadata"),
    **fields("absolute_threshold_supplied percent_threshold_supplied", "boolean", "safe_metadata"),
}
FIELDS[""] = ("object", "safe_metadata", False)
REQUIRED = {
    "": {"result", "absolute_threshold", "percent_threshold"},
    "result": {"previous_period", "current_period", "service_costs"},
    "result.previous_period": {"start_date", "end_date", "total_cost", "currency"},
    "result.current_period": {"start_date", "end_date", "total_cost", "currency"},
    "result.service_costs[]": {"service_name", "previous_cost", "current_cost"},
}


class CostDeltaPrivacyContract(ClosedProducerContract):
    """Protect original financial inputs without changing analyzer defaults."""

    scanner_id: ClassVar[str] = "cost-explorer-service-delta"
    fields: ClassVar = FIELDS

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Bind exact registered DTO and retain the supported earlier result identity."""
        if record.get("scanner_id") != cls.scanner_id:
            return None
        identities = {
            (f"{n}.scanners.cost_explorer.service_delta.evidence", "CostExplorerServiceDeltaEvidence") for n in UNIO_PROTOCOL.accepted_import_namespaces
        }
        legacy = {(f"{n}.aws.cost_explorer.result", "CostExplorerResult") for n in UNIO_PROTOCOL.accepted_import_namespaces}
        identity = (record.get("evidence_module"), record.get("evidence_type"))
        if identity in legacy and admit_evidence_schema(record) is None and record.get("provider_id", "aws") == "aws":
            return None
        if (
            admit_evidence_schema(record) is not None
            or record.get("provider_id", "aws") != "aws"
            or identity not in identities
            or record.get("serialization_status") != "serialized"
            or record.get("serialization_format") != "json-compatible-python-object"
        ):
            message = "Cost delta privacy requires its matching registered AWS DTO identity."
            raise ValueError(message)
        return cls()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Financial decimals retain signed credit amounts and canonical wire types."""
        if kind == "version":
            return type(value) is int and value in {0, 1}
        if kind in {"decimal", "financial_number"}:
            return _finite_financial(value, wire_string=kind == "decimal")
        if kind == "date":
            if not isinstance(value, str):
                return False
            try:
                parsed = date.fromisoformat(value)
            except ValueError:
                return False
            return parsed.isoformat() == value
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: object, member: str, suffix: str = "") -> list[str]:
        """Require canonical DTO fields; earlier version-zero flags may be absent."""
        failures = super().unknown_paths(value, member, suffix)
        required = REQUIRED.get(suffix, set())
        if isinstance(value, dict):
            if suffix == "" and value.get("analysis_inputs_version") == 1:
                required = required | {"analysis_inputs_version", "absolute_threshold_supplied", "percent_threshold_supplied"}
            failures.extend(member + self.prefix[1:] + ("." + suffix if suffix else "") + "." + key for key in sorted(required - value.keys()))
        return failures

    def resolve_string(self, path: str, value: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Public financial labels preserve only at reviewed standard positions."""
        decision = self.resolve(path, profile)
        if decision is None or profile != "standard":
            return decision
        if path == self.prefix + ".result.service_costs[].service_name" and value in PUBLIC_SERVICES:
            return replace(
                decision, treatment="preserve", category="safe_metadata", reason="Reviewed public provider financial service label; no leak-scan exemption."
            )
        if path.endswith(".currency") and decision.category == "cost" and value not in PUBLIC_CURRENCIES:
            return replace(
                decision,
                treatment="tokenise",
                category="resource_name",
                reason="Unrecognized currency strings protect as text; strict financial removal remains.",
            )
        return decision

    def is_literal(self, suffix: str, value: str) -> bool:
        """Financial values and labels never become known-original scan exemptions."""
        del suffix, value
        return False


def _finite_financial(value: object, *, wire_string: bool) -> bool:
    """Match SDK decimal strings and the admitted offline fixture scalar contract."""
    if isinstance(value, bool) or not isinstance(value, str | int | float | Decimal) or (wire_string and not isinstance(value, str)):
        return False
    try:
        return Decimal(str(value)).is_finite()
    except InvalidOperation:
        return False
