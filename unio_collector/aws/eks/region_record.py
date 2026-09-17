from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from decimal import Decimal


@dataclass(frozen=True)
class EksRegionRecord:  # noqa: D101
    account_id: str
    region: str
    cluster_count: int = 0
    active_cluster_count: int = 0
    nodegroup_count: int = 0
    fargate_profile_count: int = 0
    fargate_selector_count: int = 0
    cluster_without_managed_compute_count: int = 0
    public_endpoint_cluster_count: int = 0
    private_endpoint_cluster_count: int = 0
    public_endpoint_open_cidr_count: int = 0
    public_endpoint_restricted_cidr_count: int = 0
    secrets_encryption_enabled_cluster_count: int = 0
    control_plane_logging_enabled_cluster_count: int = 0
    tagged_cluster_count: int = 0
    untagged_cluster_count: int = 0
    nodegroup_desired_size_total: int = 0
    nodegroup_min_size_total: int = 0
    nodegroup_max_size_total: int = 0
    sample_cluster_names: list[str] = field(default_factory=list)
    sample_nodegroup_names: list[str] = field(default_factory=list)
    sample_fargate_profile_names: list[str] = field(default_factory=list)
    sample_versions: list[str] = field(default_factory=list)
    sample_public_endpoint_cluster_names: list[str] = field(default_factory=list)
    sample_untagged_cluster_names: list[str] = field(default_factory=list)
    sample_public_endpoint_cidrs: list[str] = field(default_factory=list)
    sample_enabled_log_types: list[str] = field(default_factory=list)
    sample_nodegroup_instance_types: list[str] = field(default_factory=list)
    sample_nodegroup_capacity_types: list[str] = field(default_factory=list)
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    permission_errors: list[str] = field(default_factory=list)
