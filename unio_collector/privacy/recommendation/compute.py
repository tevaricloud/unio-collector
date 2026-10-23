"""Exact compute_optimizer root and SDK summary field view."""

from __future__ import annotations

from typing import ClassVar

from unio_collector.privacy.recommendation.contract import RecommendationPrivacyContract
from unio_collector.privacy.recommendation.fields import ROOT_FIELDS
from unio_collector.privacy.recommendation.sdk_fields import SUMMARY_FIELDS


class ComputeRecommendationPrivacyContract(RecommendationPrivacyContract):
    """Retain independent finite source fields, never a sibling-source union."""

    scanner_id: ClassVar[str] = "compute-optimizer-recommendation-review"
    fields: ClassVar = {**ROOT_FIELDS, **SUMMARY_FIELDS["compute_optimizer"]}

    def __init__(self) -> None:
        """Create the exact source view without modifying class-level field maps."""
        super().__init__("compute_optimizer")
