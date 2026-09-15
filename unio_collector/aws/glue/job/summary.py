from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

from unio_collector.aws.analytics.evidence.rows import NumericEvidenceRows  # noqa: TC001


@dataclass(frozen=True)
class GlueJobRunSummary:  # noqa: D101
    jobs_checked: int = 0
    run_count: int = 0
    failed_run_count: int = 0
    long_running_run_count: int = 0
    high_dpu_run_count: int = 0
    total_dpu_seconds: float = 0.0
    collection_limited: bool = False
    numeric_evidence: NumericEvidenceRows | None = None
