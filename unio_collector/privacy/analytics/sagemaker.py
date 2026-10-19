"""Explicit SageMaker sampled identifiers, resource counts and billing fields."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from unio_collector.privacy.analytics.fields import COMMON, SAGEMAKER_COUNTS, SAGEMAKER_NAMES, matching_identity, names_and_counts
from unio_collector.privacy.closed_schema import ClosedProducerContract


class SageMakerPrivacyContract(ClosedProducerContract):
    """Admit only the complete enumerated producer surface, never arbitrary SDK data."""

    fields: ClassVar[dict[str, tuple[str, str, bool]]] = {**COMMON, **names_and_counts(SAGEMAKER_COUNTS, SAGEMAKER_NAMES)}

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Preserve the existing identity while rejecting foreign schema metadata."""
        return cls() if matching_identity(record, "sagemaker-cost-review", "analytics_ai.sagemaker", "SageMakerCostReviewEvidence") else None
