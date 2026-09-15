from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AwsNativeRecommendationRecord:  # noqa: D101
    source: str
    recommendation_id: str
    recommendation_type: str
    service: str
    resource_type: str
    resource_id: str
    resource_arn: str | None
    region: str
    finding: str
    confidence: str
    estimated_monthly_savings: str | None = None
    currency: str | None = None
    current_configuration: dict[str, Any] = field(default_factory=dict)
    recommended_configuration: dict[str, Any] = field(default_factory=dict)
    raw_summary: dict[str, Any] = field(default_factory=dict)
