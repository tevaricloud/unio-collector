from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class EcsRegionRecord:  # noqa: D101
    account_id: str
    region: str
    cluster_count: int = 0
    active_cluster_count: int = 0
    service_count: int = 0
    active_service_count: int = 0
    fargate_service_count: int = 0
    ec2_service_count: int = 0
    external_service_count: int = 0
    desired_task_count: int = 0
    running_task_count: int = 0
    pending_task_count: int = 0
    fargate_desired_task_count: int = 0
    fargate_running_task_count: int = 0
    ec2_desired_task_count: int = 0
    ec2_running_task_count: int = 0
    service_with_desired_tasks_count: int = 0
    service_with_pending_tasks_count: int = 0
    service_without_running_tasks_count: int = 0
    service_with_multiple_deployments_count: int = 0
    deployment_count: int = 0
    in_progress_deployment_count: int = 0
    failed_deployment_count: int = 0
    recent_service_event_count: int = 0
    task_definition_detail_collected: bool = True
    task_definition_count: int = 0
    task_definition_cpu_units_total: int = 0
    task_definition_memory_mb_total: int = 0
    task_definition_with_explicit_cpu_count: int = 0
    task_definition_with_explicit_memory_count: int = 0
    tagged_cluster_count: int = 0
    untagged_cluster_count: int = 0
    tagged_service_count: int = 0
    untagged_service_count: int = 0
    sample_cluster_names: list[str] = field(default_factory=list)
    sample_service_names: list[str] = field(default_factory=list)
    sample_services_without_running_tasks: list[str] = field(default_factory=list)
    sample_services_with_pending_tasks: list[str] = field(default_factory=list)
    sample_untagged_cluster_names: list[str] = field(default_factory=list)
    sample_untagged_service_names: list[str] = field(default_factory=list)
    sample_launch_types: list[str] = field(default_factory=list)
    sample_capacity_providers: list[str] = field(default_factory=list)
    sample_task_definition_families: list[str] = field(default_factory=list)
    sample_task_definition_sizes: list[str] = field(default_factory=list)
    sample_recent_service_events: list[str] = field(default_factory=list)
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    permission_errors: list[str] = field(default_factory=list)
