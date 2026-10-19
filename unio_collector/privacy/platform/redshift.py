"""Explicit actual redshift counts, identifiers and billing treatments."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from unio_collector.privacy.analytics.fields import matching_identity, names_and_counts
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.platform.fields import COMMON

COUNTS = (
    "cluster_count available_cluster_count paused_cluster_count total_node_count multi_az_cluster_count "
    "encrypted_cluster_count logging_enabled_cluster_count serverless_namespace_count "
    "serverless_workgroup_count serverless_base_capacity_rpu_total serverless_max_capacity_rpu_total"
)
NAMES = "sample_cluster_identifiers sample_node_types sample_serverless_names"


class RedshiftPrivacyContract(ClosedProducerContract):
    """Bind finite typed fields to the exact registered AWS producer identity."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {**COMMON, **names_and_counts(COUNTS, NAMES)}

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Reject foreign module/type/provider/schema values before transformation."""
        return cls() if matching_identity(record, "redshift-cost-review", "platform.redshift", "RedshiftCostReviewEvidence") else None
