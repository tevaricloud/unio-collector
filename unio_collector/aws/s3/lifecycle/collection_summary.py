from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field


@dataclass(frozen=True)
class S3LifecycleCollectionSummary:  # noqa: D101
    bucket_population_known: bool = False
    bucket_population_count: int = 0
    retained_bucket_count: int = 0
    operational_outer_cap: int | None = None
    outer_cap_bound: bool = False
    operational_detail_cap: int | None = None
    cap_bound: bool = False
    lifecycle_reads_attempted: int = 0
    lifecycle_reads_succeeded: int = 0
    lifecycle_reads_failed: int = 0
    versioning_reads_attempted: int = 0
    versioning_reads_succeeded: int = 0
    versioning_reads_failed: int = 0
    versioning_not_collected: int = 0
    tagging_reads_attempted: int = 0
    tagging_reads_succeeded: int = 0
    tagging_reads_failed: int = 0
    tagging_not_collected: int = 0
    replication_reads_attempted: int = 0
    replication_reads_succeeded: int = 0
    replication_reads_failed: int = 0
    replication_not_collected: int = 0
    collection_complete: bool = False
    collection_capped: bool = False
    collection_partial: bool = False
    collection_unavailable: bool = False
    collection_skipped: bool = False
    region_count: int = 0
    worker_count: int = 1
    limitations: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:  # noqa: D105
        count_fields = (
            "bucket_population_count",
            "retained_bucket_count",
            "lifecycle_reads_attempted",
            "lifecycle_reads_succeeded",
            "lifecycle_reads_failed",
            "versioning_reads_attempted",
            "versioning_reads_succeeded",
            "versioning_reads_failed",
            "versioning_not_collected",
            "tagging_reads_attempted",
            "tagging_reads_succeeded",
            "tagging_reads_failed",
            "tagging_not_collected",
            "replication_reads_attempted",
            "replication_reads_succeeded",
            "replication_reads_failed",
            "replication_not_collected",
            "region_count",
        )
        for name in count_fields:
            object.__setattr__(self, name, max(0, int(getattr(self, name))))
        object.__setattr__(self, "worker_count", max(1, int(self.worker_count)))
        for name in ("operational_outer_cap", "operational_detail_cap"):
            value = getattr(self, name)
            object.__setattr__(self, name, value if value and value > 0 else None)
        object.__setattr__(
            self,
            "limitations",
            tuple(sorted({str(value).strip() for value in self.limitations if str(value).strip()})),
        )
        if self.collection_capped or self.collection_partial or self.collection_unavailable or self.collection_skipped:
            object.__setattr__(self, "collection_complete", False)

    @property
    def collection_state(self) -> str:  # noqa: D102
        if self.collection_unavailable:
            return "unavailable"
        if self.collection_skipped:
            return "intentionally_skipped"
        if self.collection_partial:
            return "partial"
        if self.collection_capped:
            return "capped"
        return "complete" if self.collection_complete else "unavailable"

    def convert_to_dict(self) -> dict[str, object]:  # noqa: D102
        return {
            **self.__dict__,
            "collection_state": self.collection_state,
            "limitations": list(self.limitations),
        }


__all__ = ["S3LifecycleCollectionSummary"]
