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
    **{
        f"records[].operation_limitations[].{key}": ("string", "free_text", False)
        for key in (
            "api_action",
            "status",
            "error_classification",
        )
    },
    "records[].operation_limitations[].error_code": ("string", "free_text", True),
}


class BedrockPrivacyContract(ClosedProducerContract):
    """Bind exact typed paths to a recognized producer, never to other scanners."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = FIELDS

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Select only matching legacy/v1 identities; conflicts fail before traversal."""
        if record.get("scanner_id") != BEDROCK_SCANNER_ID:
            return None
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
