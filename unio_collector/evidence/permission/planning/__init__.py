"""Collector-safe permission planning contracts and renderers."""

from unio_collector.evidence.permission.planning.aws_scope import AwsPolicyExecutionScope
from unio_collector.evidence.permission.planning.builder import PermissionPlanBuilder
from unio_collector.evidence.permission.planning.degradation import (
    DEGRADATION_RECORD_SCHEMA_VERSION,
    KMS_DESCRIBE_KEY_POLICY_SOURCE_UNKNOWN,
    PermissionDegradationRecord,
    build_degradation_records_from_ledger,
    build_legacy_degradation_records,
    build_record_id,
    sort_degradation_records,
)
from unio_collector.evidence.permission.planning.degradation_context import (
    DegradationContext,
)
from unio_collector.evidence.permission.planning.limitation_category import (
    limitation_category_for_record,
    limitation_category_for_values,
)
from unio_collector.evidence.permission.planning.outcome_effect import (
    confidence_effect_for_outcome,
    downstream_effect_for_outcome,
    evidence_interpretation_for_outcome,
)
from unio_collector.evidence.permission.planning.plan import PermissionPlan
from unio_collector.evidence.permission.planning.preview import PermissionPreviewBuilder
from unio_collector.evidence.permission.planning.record_builder import (
    build_degradation_records,
)
from unio_collector.evidence.permission.planning.rendering import (
    AwsIamPolicyRenderer,
    PermissionPlanJsonRenderer,
    PermissionPlanSummaryRenderer,
)
from unio_collector.evidence.permission.planning.requirement import (
    PermissionRequirement,
    ResourceScope,
)
from unio_collector.evidence.permission.planning.requirement_type import RequirementType
from unio_collector.evidence.permission.planning.summary_stats import (
    summarize_degradation_records,
)

__all__ = [
    "DEGRADATION_RECORD_SCHEMA_VERSION",
    "KMS_DESCRIBE_KEY_POLICY_SOURCE_UNKNOWN",
    "AwsIamPolicyRenderer",
    "AwsPolicyExecutionScope",
    "DegradationContext",
    "PermissionDegradationRecord",
    "PermissionPlan",
    "PermissionPlanBuilder",
    "PermissionPlanJsonRenderer",
    "PermissionPlanSummaryRenderer",
    "PermissionPreviewBuilder",
    "PermissionRequirement",
    "RequirementType",
    "ResourceScope",
    "build_degradation_records",
    "build_degradation_records_from_ledger",
    "build_legacy_degradation_records",
    "build_record_id",
    "confidence_effect_for_outcome",
    "downstream_effect_for_outcome",
    "evidence_interpretation_for_outcome",
    "limitation_category_for_record",
    "limitation_category_for_values",
    "sort_degradation_records",
    "summarize_degradation_records",
]
