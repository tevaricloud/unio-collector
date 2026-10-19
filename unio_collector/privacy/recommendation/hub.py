"""Exact cost_optimization_hub root and SDK summary field view."""

from __future__ import annotations

from typing import ClassVar

from unio_collector.privacy.recommendation.contract import RecommendationPrivacyContract
from unio_collector.privacy.recommendation.fields import ROOT_FIELDS
from unio_collector.privacy.recommendation.sdk_fields import SUMMARY_FIELDS


class HubRecommendationPrivacyContract(RecommendationPrivacyContract):
    """Retain independent finite source fields, never a sibling-source union."""

    scanner_id: ClassVar[str] = "cost-optimization-hub-recommendation-review"
    fields: ClassVar = {**ROOT_FIELDS, **SUMMARY_FIELDS["cost_optimization_hub"]}

    def __init__(self) -> None:
        """Create the exact source view without modifying class-level field maps."""
        super().__init__("cost_optimization_hub")
