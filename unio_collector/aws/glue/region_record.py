from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from unio_collector.aws.analytics.evidence.rows import NumericEvidenceRows  # noqa: TC001

if TYPE_CHECKING:
    from decimal import Decimal

    from unio_collector.aws.cost_explorer import UsageTypeCostSummary


@dataclass(frozen=True)
class GlueRegionRecord:  # noqa: D101
    account_id: str
    region: str
    crawler_count: int = 0
    scheduled_crawler_count: int = 0
    job_count: int = 0
    high_capacity_job_count: int = 0
    total_configured_workers: int = 0
    sample_crawler_names: list[str] = field(default_factory=list)
    sample_job_names: list[str] = field(default_factory=list)
    sample_worker_types: list[str] = field(default_factory=list)
    job_run_jobs_checked: int = 0
    job_run_count: int = 0
    failed_job_run_count: int = 0
    long_running_job_run_count: int = 0
    high_dpu_job_run_count: int = 0
    total_dpu_seconds: float = 0.0
    job_run_collection_limited: bool = False
    service_current_cost: Decimal | None = None
    service_previous_cost: Decimal | None = None
    service_cost_currency: str | None = None
    regional_current_cost: Decimal | None = None
    regional_cost_currency: str | None = None
    regional_cost_record_count: int = 0
    top_usage_type_costs: list[UsageTypeCostSummary] = field(default_factory=list)
    permission_errors: list[str] = field(default_factory=list)
    collection_evidence_version: int = 0
    job_numeric_evidence: NumericEvidenceRows | None = None
    run_numeric_evidence: NumericEvidenceRows | None = None
    configured_run_duration: int | None = None
    configured_run_dpu: float | None = None
    policy_input_source: int = 0
