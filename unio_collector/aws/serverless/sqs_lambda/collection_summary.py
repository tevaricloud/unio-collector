from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SqsLambdaCollectionSummary:  # noqa: D101
    mappings_observed: int = 0
    retained_mappings: int = 0
    mapping_cap_applied: bool = False
    collection_complete: bool = False
    collection_capped: bool = False
    collection_partial: bool = False
    collection_unavailable: bool = False
    metric_summary_count: int = 0
    metric_failure_count: int = 0
    metric_retrieval_complete: bool = True
    operational_mapping_cap: int | None = None
    limitations: tuple[str, ...] = field(default_factory=tuple)

    def convert_to_dict(self) -> dict[str, object]:  # noqa: D102
        return {
            "mappings_observed": self.mappings_observed,
            "retained_mappings": self.retained_mappings,
            "mapping_cap_applied": self.mapping_cap_applied,
            "collection_complete": self.collection_complete,
            "collection_capped": self.collection_capped,
            "collection_partial": self.collection_partial,
            "collection_unavailable": self.collection_unavailable,
            "metric_summary_count": self.metric_summary_count,
            "metric_failure_count": self.metric_failure_count,
            "metric_retrieval_complete": self.metric_retrieval_complete,
            "operational_mapping_cap": self.operational_mapping_cap,
            "limitations": list(self.limitations),
        }


__all__ = ["SqsLambdaCollectionSummary"]
