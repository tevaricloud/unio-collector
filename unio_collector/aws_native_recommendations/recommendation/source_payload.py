from __future__ import annotations  # noqa: D100

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.aws_native_recommendations.recommendation.record import (
        AwsNativeRecommendationRecord,
    )


@dataclass(frozen=True)
class AwsNativeRecommendationSourcePayload:  # noqa: D101
    source: str
    status: str
    account_id: str
    regions: tuple[str, ...]
    recommendation_count: int
    summary_count: int
    records: tuple[AwsNativeRecommendationRecord, ...] = ()
    summaries: tuple[dict[str, Any], ...] = ()
    warnings: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:  # noqa: D102
        return {
            "source": self.source,
            "status": self.status,
            "account_id": self.account_id,
            "regions": list(self.regions),
            "recommendation_count": self.recommendation_count,
            "summary_count": self.summary_count,
            "records": [asdict(record) for record in self.records],
            "summaries": list(self.summaries),
            "warnings": list(self.warnings),
            "limitations": list(self.limitations),
            "metadata": _to_json_metadata(self.metadata or {}),
        }


def _to_json_metadata(value: Any) -> Any:  # noqa: ANN401
    if isinstance(value, dict):
        return {str(key): _to_json_metadata(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_to_json_metadata(item) for item in value]
    return value
