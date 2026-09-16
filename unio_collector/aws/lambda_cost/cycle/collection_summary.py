from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field


@dataclass(frozen=True)
class LambdaCostCycleCollectionSummary:  # noqa: D101
    s3_notification_detail_mode: str = "full"
    bucket_population_known: bool = False
    bucket_population_count: int = 0
    bucket_notifications_attempted: int = 0
    notification_success_count: int = 0
    notification_failure_count: int = 0
    collection_complete: bool = False
    collection_capped: bool = False
    collection_partial: bool = False
    collection_unavailable: bool = False
    detail_intentionally_skipped: bool = False
    operational_bucket_cap: int | None = None
    limitations: tuple[str, ...] = field(default_factory=tuple)

    def convert_to_dict(self) -> dict[str, object]:  # noqa: D102
        return {
            "s3_notification_detail_mode": self.s3_notification_detail_mode,
            "bucket_population_known": self.bucket_population_known,
            "bucket_population_count": self.bucket_population_count,
            "bucket_notifications_attempted": self.bucket_notifications_attempted,
            "notification_success_count": self.notification_success_count,
            "notification_failure_count": self.notification_failure_count,
            "collection_complete": self.collection_complete,
            "collection_capped": self.collection_capped,
            "collection_partial": self.collection_partial,
            "collection_unavailable": self.collection_unavailable,
            "detail_intentionally_skipped": self.detail_intentionally_skipped,
            "operational_bucket_cap": self.operational_bucket_cap,
            "limitations": list(self.limitations),
        }


__all__ = ["LambdaCostCycleCollectionSummary"]
