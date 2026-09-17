from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CloudFrontMetricSummary:  # noqa: D101
    metric_collection_status: str = "not_requested"
    metric_collection_reason: str = "CloudFront metric enrichment was not requested."
    metric_distribution_count: int = 0
    metric_datapoint_count: int = 0
    request_sum: int = 0
    bytes_downloaded_sum: int = 0
    bytes_uploaded_sum: int = 0
    four_xx_error_rate_average: float | None = None
    five_xx_error_rate_average: float | None = None
    metric_collection_errors: list[str] = field(default_factory=list)
