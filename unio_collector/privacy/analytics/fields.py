"""Closed reviewed DTO paths; never derive privacy admission from observed keys."""

from __future__ import annotations

from typing import Any

from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.s3.fields import fields
from unio_collector.scanners.scanner.schema import admit_evidence_schema

COMMON = {
    "": ("object", "safe_metadata", False),
    **fields("records regions", "array"),
    **fields("records[]", "object"),
    **fields("regions[] records[].region", "string", "region"),
    **fields("records[].account_id", "string", "aws_account_id"),
    **fields("records[].regional_cost_record_count", "count", "summary_count"),
    **fields("records[].service_current_cost records[].service_previous_cost records[].regional_current_cost", "money", "cost", nullable=True),
    **fields("records[].service_cost_currency records[].regional_cost_currency", "string", "cost", nullable=True),
    **fields("records[].permission_errors", "array", "removed_diagnostic"),
    **fields("records[].permission_errors[]", "string", "removed_diagnostic"),
    **fields("records[].top_usage_type_costs", "array", "cost"),
    **fields("records[].top_usage_type_costs[]", "object", "cost"),
    **fields("records[].top_usage_type_costs[].usage_type", "string", "resource_name"),
    **fields("records[].top_usage_type_costs[].current_cost", "money", "cost"),
    **fields("records[].top_usage_type_costs[].currency", "string", "cost"),
    **fields("records[].top_usage_type_costs[].record_count", "count", "summary_count"),
}
GLUE_COUNTS = (
    "crawler_count scheduled_crawler_count job_count high_capacity_job_count total_configured_workers "
    "job_run_jobs_checked job_run_count failed_job_run_count long_running_job_run_count high_dpu_job_run_count"
)
SAGEMAKER_COUNTS = (
    "notebook_count running_notebook_count endpoint_count in_service_endpoint_count endpoint_variant_count "
    "provisioned_endpoint_instance_count serverless_endpoint_variant_count async_endpoint_count training_job_count "
    "active_training_job_count processing_job_count active_processing_job_count transform_job_count "
    "active_transform_job_count"
)
GLUE_NAMES = "sample_crawler_names sample_job_names sample_worker_types"
SAGEMAKER_NAMES = (
    "sample_notebook_names sample_endpoint_names sample_endpoint_instance_types sample_training_job_names "
    "sample_processing_job_names sample_transform_job_names"
)


def names_and_counts(counts: str, names: str) -> dict[str, tuple[str, str, bool]]:
    """Expand explicit field names, protecting every sampled identifier whole."""
    return {
        **fields(" ".join("records[]." + name for name in counts.split()), "count", "summary_count"),
        **fields(" ".join("records[]." + name for name in names.split()), "array", "resource_name"),
        **fields(" ".join("records[]." + name + "[]" for name in names.split()), "string", "resource_name"),
    }


def matching_identity(record: dict[str, Any], scanner: str, module: str, evidence_type: str) -> bool:
    """Recognize only the exact legacy AWS DTO identity before inspecting fields."""
    if record.get("scanner_id") != scanner:
        return False
    schema = admit_evidence_schema(record)
    if (
        schema is not None
        or record.get("provider_id", "aws") != "aws"
        or (record.get("evidence_module"), record.get("evidence_type"))
        not in {(f"{namespace}.scanners.{module}.evidence", evidence_type) for namespace in UNIO_PROTOCOL.accepted_import_namespaces}
    ):
        message = "Analytics privacy schema requires its matching legacy AWS evidence identity."
        raise ValueError(message)
    return True
