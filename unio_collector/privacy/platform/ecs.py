"""Explicit actual ECS operational counts, samples and billing privacy."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any, ClassVar, Self

from unio_collector.privacy.analytics.fields import matching_identity, names_and_counts
from unio_collector.privacy.closed_schema import PREFIX, ClosedProducerContract
from unio_collector.privacy.platform.fields import COMMON
from unio_collector.privacy.s3.fields import fields

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision

COUNTS = (
    "cluster_count active_cluster_count service_count active_service_count fargate_service_count ec2_service_count "
    "external_service_count desired_task_count running_task_count pending_task_count fargate_desired_task_count "
    "fargate_running_task_count ec2_desired_task_count ec2_running_task_count service_with_desired_tasks_count "
    "service_with_pending_tasks_count service_without_running_tasks_count service_with_multiple_deployments_count "
    "deployment_count in_progress_deployment_count failed_deployment_count recent_service_event_count "
    "task_definition_count task_definition_cpu_units_total task_definition_memory_mb_total "
    "task_definition_with_explicit_cpu_count task_definition_with_explicit_memory_count tagged_cluster_count "
    "untagged_cluster_count tagged_service_count untagged_service_count"
)
NAMES = (
    "sample_cluster_names sample_service_names sample_services_without_running_tasks "
    "sample_services_with_pending_tasks sample_untagged_cluster_names sample_untagged_service_names "
    "sample_launch_types sample_capacity_providers sample_task_definition_families sample_task_definition_sizes"
)


class EcsPrivacyContract(ClosedProducerContract):
    """Protect arbitrary sample labels whole without changing precomputed facts."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {
        **COMMON,
        **names_and_counts(COUNTS, NAMES),
        **fields("records[].task_definition_detail_collected", "boolean"),
        **fields("records[].sample_recent_service_events", "array", "free_text"),
        **fields("records[].sample_recent_service_events[]", "string", "free_text"),
    }

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Require exact legacy AWS module/type/schema identity before payload handling."""
        return cls() if matching_identity(record, "ecs-cost-governance-review", "platform.ecs", "EcsCostGovernanceReviewEvidence") else None

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Protect whole arbitrary service-event prose while retaining its presence."""
        decision = super().resolve(path, profile)
        return replace(decision, treatment="tokenise") if decision is not None and path == PREFIX + ".records[].sample_recent_service_events[]" else decision
