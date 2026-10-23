"""Closed privacy contract for the existing Bedrock v1 collection producer."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.closed_schema import PREFIX as _PAYLOAD_PREFIX
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.scanners.scanner.schema import BEDROCK_SCANNER_ID, BEDROCK_SCHEMA_ID, admit_evidence_schema

PREFIX = _PAYLOAD_PREFIX


FIELDS: dict[str, tuple[str, str, bool]] = {
    "": ("object", "safe_metadata", False),
    "records": ("array", "safe_metadata", False),
    "records[]": ("object", "safe_metadata", False),
    "regions": ("array", "region", False),
    "regions[]": ("string", "region", False),
    "records[].account_id": ("string", "aws_account_id", False),
    "records[].region": ("string", "region", False),
    **{
        f"records[].{key}": ("count", "safe_metadata", False)
        for key in (
            "foundation_model_count",
            "custom_model_count",
            "provisioned_throughput_count",
            "inference_profile_count",
            "agent_count",
            "knowledge_base_count",
            "regional_cost_record_count",
        )
    },
    **{
        f"records[].{key}": ("array", "resource_name", False)
        for key in (
            "sample_foundation_model_ids",
            "sample_custom_model_names",
            "sample_provisioned_model_names",
            "sample_inference_profile_names",
            "sample_agent_names",
            "sample_knowledge_base_names",
        )
    },
    **{
        f"records[].{key}[]": ("string", "resource_name", False)
        for key in (
            "sample_foundation_model_ids",
            "sample_custom_model_names",
            "sample_provisioned_model_names",
            "sample_inference_profile_names",
            "sample_agent_names",
            "sample_knowledge_base_names",
        )
    },
    **{
        f"records[].{key}": ("money", "cost", True)
        for key in (
            "service_current_cost",
            "service_previous_cost",
            "regional_current_cost",
        )
    },
    **{f"records[].{key}": ("string", "cost", True) for key in ("service_cost_currency", "regional_cost_currency")},
    "records[].top_usage_type_costs": ("array", "cost", False),
    "records[].top_usage_type_costs[]": ("object", "cost", False),
    "records[].top_usage_type_costs[].usage_type": ("string", "free_text", False),
    "records[].top_usage_type_costs[].current_cost": ("money", "cost", False),
    "records[].top_usage_type_costs[].currency": ("string", "cost", False),
    "records[].top_usage_type_costs[].record_count": ("count", "safe_metadata", False),
    "records[].permission_errors": ("array", "removed_diagnostic", False),
    "records[].permission_errors[]": ("string", "removed_diagnostic", False),
    "records[].operation_limitations": ("array", "safe_metadata", False),
    "records[].operation_limitations[]": ("object", "safe_metadata", False),
    "records[].operation_limitations[].api_action": ("capability_action", "safe_metadata", False),
    "records[].operation_limitations[].status": ("capability_status", "safe_metadata", False),
    "records[].operation_limitations[].error_classification": ("capability_classification", "safe_metadata", False),
    "records[].operation_limitations[].error_code": ("capability_code", "safe_metadata", True),
}


CAPABILITY_VOCABULARIES = {
    "capability_action": frozenset({"bedrock:ListCustomModels"}),
    "capability_status": frozenset({"skipped_client_model", "unsupported_endpoint_operation"}),
    "capability_classification": frozenset({"unsupported_operation"}),
    "capability_code": frozenset({"UnsupportedClientModelOperation", "UnknownOperationException", "ValidationException"}),
}


def is_capability_value(value: object, kind: str, *, nullable: bool) -> bool:
    """Admit only the actual filtered SDK capability vocabulary and declared nulls."""
    return (value is None and nullable) or (isinstance(value, str) and value in CAPABILITY_VOCABULARIES.get(kind, frozenset()))


class BedrockPrivacyContract(ClosedProducerContract):
    """Bind exact typed paths to a recognized producer, never to other scanners."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Select only matching legacy/v1 identities; conflicts fail before traversal."""
        if record.get("scanner_id") != BEDROCK_SCANNER_ID:
            return None
        if record.get("provider_id", "aws") != "aws":
            message = "Bedrock privacy schema requires its AWS provider identity."
            raise ValueError(message)
        schema = admit_evidence_schema(record)
        if schema is not None:
            if schema.schema_id != BEDROCK_SCHEMA_ID:
                message = "Bedrock privacy contract requires its recognized v1 evidence schema."
                raise ValueError(message)
        elif (record.get("evidence_module"), record.get("evidence_type")) not in {
            (f"{namespace}.scanners.analytics_ai.bedrock.evidence", "BedrockCostReviewEvidence") for namespace in UNIO_PROTOCOL.accepted_import_namespaces
        }:
            message = "Bedrock privacy contract requires matching collection evidence identity."
            raise ValueError(message)
        return cls()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        if kind in CAPABILITY_VOCABULARIES:
            return is_capability_value(value, kind, nullable=nullable)
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Keep the exact capability DTO complete before any profile treatment."""
        failures = super().unknown_paths(value, member, suffix)
        if suffix == "records[].operation_limitations[]" and isinstance(value, dict):
            required = {"api_action", "status", "error_classification", "error_code"}
            failures.extend(member + self.prefix[1:] + "." + suffix + "." + key for key in sorted(required - value.keys()))
            codes = (
                ("UnsupportedClientModelOperation",)
                if value.get("status") == "skipped_client_model"
                else (None, "UnknownOperationException", "ValidationException")
            )
            if value.get("error_code") not in codes:
                failures.append(member + self.prefix[1:] + "." + suffix + ".capability_contract")
        return failures

    def admitted_operation_limitation(self, value: object) -> bool:
        """Require the exact action/status/classification and status-specific code pair."""
        return isinstance(value, dict) and not self.unknown_paths(value, "", "records[].operation_limitations[]")

    def is_public_capability(self, suffix: str, value: object) -> bool:
        """Normalize only declared finite control roles inside an admitted parent."""
        spec = self.fields.get(suffix)
        return spec is not None and spec[0] in CAPABILITY_VOCABULARIES and is_capability_value(value, spec[0], nullable=spec[2])
