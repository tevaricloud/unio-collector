from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

from unio_collector.aws.analytics.evidence.rows import NumericEvidenceRows  # noqa: TC001


@dataclass(frozen=True)
class AthenaQueryExecutionSummary:  # noqa: D101
    workgroups_checked: int = 0
    query_execution_count: int = 0
    failed_query_execution_count: int = 0
    long_running_query_count: int = 0
    high_bytes_scanned_query_count: int = 0
    total_bytes_scanned: int = 0
    total_engine_execution_ms: int = 0
    collection_limited: bool = False
    numeric_evidence: NumericEvidenceRows | None = None
