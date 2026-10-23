"""Explicit actual EKS operational counts, samples and billing privacy."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from unio_collector.privacy.analytics.fields import matching_identity, names_and_counts
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.platform.fields import COMMON

COUNTS = (
    "cluster_count active_cluster_count nodegroup_count fargate_profile_count fargate_selector_count "
    "cluster_without_managed_compute_count public_endpoint_cluster_count private_endpoint_cluster_count "
    "public_endpoint_open_cidr_count public_endpoint_restricted_cidr_count secrets_encryption_enabled_cluster_count "
    "control_plane_logging_enabled_cluster_count tagged_cluster_count untagged_cluster_count "
    "nodegroup_desired_size_total nodegroup_min_size_total nodegroup_max_size_total"
)
NAMES = (
    "sample_cluster_names sample_nodegroup_names sample_fargate_profile_names sample_versions "
    "sample_public_endpoint_cluster_names sample_untagged_cluster_names sample_public_endpoint_cidrs "
    "sample_enabled_log_types sample_nodegroup_instance_types sample_nodegroup_capacity_types"
)


class EksPrivacyContract(ClosedProducerContract):
    """Protect arbitrary sample labels whole without changing precomputed facts."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {**COMMON, **names_and_counts(COUNTS, NAMES)}

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Require exact legacy AWS module/type/schema identity before payload handling."""
        return cls() if matching_identity(record, "eks-cost-risk-review", "platform.eks", "EksCostRiskReviewEvidence") else None
