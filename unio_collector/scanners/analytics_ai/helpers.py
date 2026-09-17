from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.analytics.ai import (
    AnalyticsAiInventoryCollector,
    AthenaRegionRecord,
    BedrockRegionRecord,
    GlueRegionRecord,
    SageMakerRegionRecord,
)
from unio_collector.scanners.analytics_ai.execution_detail import (
    AnalyticsAiExecutionDetailSpec,
)
from unio_collector.scanners.cost_context import enrich_records_with_cost_context

if TYPE_CHECKING:
    from unio_collector.aws.athena.query.scope import AthenaQueryCollectionScope
    from unio_collector.aws.glue.job.scope import GlueJobCollectionScope
    from unio_collector.scanners.base import ScannerContext

ANALYTICS_AI_COST_EXPLORER_SERVICE_NAMES: dict[str, tuple[str, ...]] = {
    "athena-query-efficiency-review": ("Amazon Athena",),
    "glue-job-crawler-cost-review": ("AWS Glue",),
    "sagemaker-cost-review": ("Amazon SageMaker",),
    "bedrock-cost-review": ("Amazon Bedrock",),
}

type AnalyticsAiRecord = AthenaRegionRecord | GlueRegionRecord | SageMakerRegionRecord | BedrockRegionRecord

ANALYTICS_AI_EXECUTION_DETAIL_SPECS: dict[str, AnalyticsAiExecutionDetailSpec] = {
    "athena-query-efficiency-review": AnalyticsAiExecutionDetailSpec(
        service_label="Athena",
        resource_label="workgroup, data catalog, or query execution",
        resource_count_fields=(
            "workgroup_count",
            "data_catalog_count",
            "query_execution_count",
        ),
        detail_count_fields=(
            "workgroup_count",
            "unbounded_workgroup_count",
            "enforced_workgroup_count",
            "data_catalog_count",
            "query_execution_count",
            "high_bytes_scanned_query_count",
        ),
    ),
    "glue-job-crawler-cost-review": AnalyticsAiExecutionDetailSpec(
        service_label="Glue",
        resource_label="crawler, job, or job run",
        resource_count_fields=("crawler_count", "job_count", "job_run_count"),
        detail_count_fields=(
            "crawler_count",
            "scheduled_crawler_count",
            "job_count",
            "high_capacity_job_count",
            "job_run_count",
            "failed_job_run_count",
            "high_dpu_job_run_count",
        ),
    ),
    "sagemaker-cost-review": AnalyticsAiExecutionDetailSpec(
        service_label="SageMaker",
        resource_label="notebook, endpoint, or job",
        resource_count_fields=(
            "notebook_count",
            "endpoint_count",
            "training_job_count",
            "processing_job_count",
            "transform_job_count",
        ),
        detail_count_fields=(
            "notebook_count",
            "running_notebook_count",
            "endpoint_count",
            "in_service_endpoint_count",
            "training_job_count",
            "processing_job_count",
            "transform_job_count",
        ),
    ),
    "bedrock-cost-review": AnalyticsAiExecutionDetailSpec(
        service_label="Bedrock",
        resource_label="account resource or regional catalogue signal",
        resource_count_fields=(
            "custom_model_count",
            "provisioned_throughput_count",
            "inference_profile_count",
            "agent_count",
            "knowledge_base_count",
        ),
        detail_count_fields=(
            "foundation_model_count",
            "custom_model_count",
            "provisioned_throughput_count",
            "inference_profile_count",
            "agent_count",
            "knowledge_base_count",
        ),
    ),
}


def build_analytics_ai_collector(  # noqa: D103
    context: ScannerContext,
    *,
    athena_query_execution_options: AthenaQueryCollectionScope | None = None,
    glue_job_run_options: GlueJobCollectionScope | None = None,
) -> AnalyticsAiInventoryCollector:
    return context.security.create_regional_inventory_collector(
        AnalyticsAiInventoryCollector,
        collector_name="AnalyticsAiInventoryCollector",
        athena_query_execution_options=athena_query_execution_options,
        glue_job_run_options=glue_job_run_options,
    )


def add_analytics_ai_cost_context[TAnalyticsAiRecord: AnalyticsAiRecord](  # noqa: D103
    records: list[TAnalyticsAiRecord],
    context: ScannerContext,
) -> list[TAnalyticsAiRecord]:
    service_names = ANALYTICS_AI_COST_EXPLORER_SERVICE_NAMES.get(
        context.definition.scanner_id,
        (),
    )
    if not records or not service_names:
        return records
    try:
        service_costs = context.costs.collect_service_costs()
        regional_costs = context.costs.collect_daily_costs(
            group_keys=("SERVICE", "REGION"),
        )
        usage_type_costs = context.costs.collect_daily_costs(
            group_keys=("SERVICE", "USAGE_TYPE"),
        )
    except Exception as exc:  # noqa: BLE001
        code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
        context.warnings.add(
            (f"Cost Explorer context was unavailable for this analytics and AI scanner; metadata findings continued ({code})."),
        )
        return records
    return enrich_records_with_cost_context(
        records,
        service_names=service_names,
        service_costs=service_costs,
        daily_costs=regional_costs,
        usage_type_costs=usage_type_costs,
    )


def record_analytics_ai_execution_detail[TAnalyticsAiRecord: AnalyticsAiRecord](  # noqa: D103
    context: ScannerContext,
    records: list[TAnalyticsAiRecord],
    *,
    regions: list[str],
) -> None:
    context.warnings.add_coverage_note(
        build_analytics_ai_execution_detail_note(
            context.definition.scanner_id,
            records,
            regions=regions,
        ),
    )


def build_analytics_ai_execution_detail_note[TAnalyticsAiRecord: AnalyticsAiRecord](  # noqa: D103
    scanner_id: str,
    records: list[TAnalyticsAiRecord],
    *,
    regions: list[str],
) -> dict[str, Any]:
    spec = ANALYTICS_AI_EXECUTION_DETAIL_SPECS.get(
        scanner_id,
        AnalyticsAiExecutionDetailSpec(
            service_label="analytics or AI service",
            resource_label="metadata record",
            resource_count_fields=(),
            detail_count_fields=(),
        ),
    )
    resource_count = sum_analytics_ai_record_fields(
        records,
        spec.resource_count_fields,
    )
    detail_counts = {field: sum_analytics_ai_record_fields(records, (field,)) for field in spec.detail_count_fields}
    if any(getattr(record, "collection_evidence_version", 0) == 1 for record in records):
        for field in ("high_bytes_scanned_query_count", "high_capacity_job_count", "high_dpu_job_run_count"):
            detail_counts.pop(field, None)
    billing_context_count = sum(1 for record in records if has_analytics_ai_cost_context(record))
    permission_error_count = sum(len(getattr(record, "permission_errors", [])) for record in records)
    if billing_context_count:
        billing_phrase = f"service, regional, or usage-type billing context was available on {billing_context_count} record(s)"
    else:
        billing_phrase = "no matching service, regional, or usage-type billing context was attached to the collected metadata"
    return {
        "note_type": "execution_detail",
        "scanner_id": scanner_id,
        "scope_area": "analytics_ai_metadata",
        "summary": (
            f"{spec.service_label} cost review collected {resource_count} "
            f"{spec.resource_label}(s) across {len(records)} regional "
            f"record(s); {billing_phrase}. This is not resource-level usage "
            "or unit-cost attribution."
        ),
        "regions_attempted": list(regions),
        "region_record_count": len(records),
        "resource_label": spec.resource_label,
        "resource_count": resource_count,
        "detail_counts": detail_counts,
        "billing_context_record_count": billing_context_count,
        "permission_error_count": permission_error_count,
        "result_scope": "metadata_with_optional_billing_context",
        "impact": (
            "This read-only note explains analytics and AI metadata plus billing context coverage; it does not run queries, invoke models, or change resources."
        ),
    }


def has_analytics_ai_cost_context(record: AnalyticsAiRecord) -> bool:  # noqa: D103
    return bool(
        getattr(record, "service_current_cost", None) is not None
        or getattr(record, "regional_current_cost", None) is not None
        or getattr(record, "top_usage_type_costs", []),
    )


def sum_analytics_ai_record_fields[TAnalyticsAiRecord: AnalyticsAiRecord](  # noqa: D103
    records: list[TAnalyticsAiRecord],
    fields: tuple[str, ...],
) -> int:
    total = 0
    for record in records:
        for field_name in fields:
            value = getattr(record, field_name, 0)
            if isinstance(value, bool):
                total += int(value)
            elif isinstance(value, int):
                total += value
    return total
