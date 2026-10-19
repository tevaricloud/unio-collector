"""Explicit actual opensearch counts, identifiers and billing treatments."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from unio_collector.privacy.analytics.fields import matching_identity, names_and_counts
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.platform.fields import COMMON

COUNTS = (
    "domain_count processing_domain_count total_instance_count multi_az_domain_count "
    "dedicated_master_domain_count warm_storage_domain_count ebs_enabled_domain_count total_ebs_volume_gb"
)
NAMES = "sample_domain_names sample_engine_versions sample_instance_types"


class OpenSearchPrivacyContract(ClosedProducerContract):
    """Bind finite typed fields to the exact registered AWS producer identity."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {**COMMON, **names_and_counts(COUNTS, NAMES)}

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Reject foreign module/type/provider/schema values before transformation."""
        return cls() if matching_identity(record, "opensearch-cost-review", "platform.opensearch", "OpenSearchCostReviewEvidence") else None
