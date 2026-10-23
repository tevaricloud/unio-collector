"""Closed actual SQS-to-Lambda polling inventory and collection-summary contract."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.s3.fields import fields
from unio_collector.privacy.serverless.metric import METRIC_FIELDS, ServerlessMetricContract
from unio_collector.scanners.scanner.schema import admit_evidence_schema

SCANNER = "sqs-lambda-polling-cost-review"
SUMMARY = "metadata.collection_summary."


class SqsPollingPrivacyContract(ServerlessMetricContract):
    """Keep identifiers and prose protected while preserving typed operational evidence."""

    roles: ClassVar[frozenset[tuple[str, str, str]]] = frozenset(
        {
            ("AWS/Lambda", "Invocations", "Sum"),
            ("AWS/Lambda", "Errors", "Sum"),
            ("AWS/Lambda", "Duration", "Average"),
            ("AWS/SQS", "NumberOfMessagesReceived", "Sum"),
            ("AWS/SQS", "NumberOfEmptyReceives", "Sum"),
            ("AWS/SQS", "ApproximateAgeOfOldestMessage", "Maximum"),
        }
    )
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {
        "": ("object", "safe_metadata", False),
        **fields("records regions", "array"),
        **fields("records[] metadata metadata.collection_summary", "object"),
        **fields("regions[] records[].region", "string", "region"),
        **fields("records[].account_id", "string", "aws_account_id"),
        **fields("records[].uuid", "string", "resource_id"),
        **fields("records[].function_arn", "string", "arn", nullable=True),
        **fields("records[].queue_arn", "string", "arn"),
        **fields("records[].function_name", "string", "resource_name", nullable=True),
        **fields("records[].queue_name", "string", "resource_name"),
        **fields("records[].state", "string", "free_text", nullable=True),
        **fields("records[].batch_size metadata.max_mappings_per_region " + SUMMARY + "operational_mapping_cap", "count", "summary_count", nullable=True),
        **fields("records[].derived_metric_policy_fields_populated", "boolean"),
        **fields("metadata.metric_collection_mode", "mode"),
        **fields(
            " ".join(SUMMARY + key for key in ("mappings_observed", "retained_mappings", "metric_summary_count", "metric_failure_count")),
            "count",
            "summary_count",
        ),
        **fields(
            " ".join(
                SUMMARY + key
                for key in (
                    "mapping_cap_applied",
                    "collection_complete",
                    "collection_capped",
                    "collection_partial",
                    "collection_unavailable",
                    "metric_retrieval_complete",
                )
            ),
            "boolean",
        ),
        **fields(SUMMARY + "limitations", "array"),
        **fields(SUMMARY + "limitations[]", "string", "free_text"),
        **METRIC_FIELDS,
    }

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Require the registered legacy AWS InventoryEvidence identity before payload admission."""
        if record.get("scanner_id") != SCANNER:
            return None
        if (
            admit_evidence_schema(record) is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type"))
            not in {(namespace + ".scanners.inventory_evidence", "InventoryEvidence") for namespace in UNIO_PROTOCOL.accepted_import_namespaces}
        ):
            message = "SQS polling privacy requires its exact legacy AWS evidence identity."
            raise ValueError(message)
        return cls()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        if kind == "mode":
            return value == "batched_cloudwatch_metric_data"
        return super()._valid(value, kind, nullable=nullable)

    def is_literal(self, suffix: str, value: object) -> bool:
        """Only the exact collection mode and independently guarded metric roles are public."""
        return (suffix == "metadata.metric_collection_mode" and value == "batched_cloudwatch_metric_data") or super().is_literal(suffix, value)
