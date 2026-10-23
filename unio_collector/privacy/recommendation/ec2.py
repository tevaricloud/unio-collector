"""Exact ec2_instance provider recommendation field view."""

from __future__ import annotations

from typing import ClassVar

from unio_collector.privacy.recommendation.fields import RECORD_FIELDS
from unio_collector.privacy.recommendation.record import RecommendationRecordContract
from unio_collector.privacy.recommendation.sdk_fields import RECORD_FIELDS as SDK_FIELDS


class Ec2RecommendationContract(RecommendationRecordContract):
    """Bind one finite provider resource kind without shared mutable field state."""

    fields: ClassVar = {**RECORD_FIELDS, **{"records[]." + key: spec for key, spec in SDK_FIELDS["ec2_instance"].items()}}

    def __init__(self) -> None:
        """Create an independent view with immutable class-declared field selection."""
        super().__init__("compute_optimizer", "ec2_instance")
