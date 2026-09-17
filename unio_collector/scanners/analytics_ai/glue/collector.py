from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.glue.job.scope import GlueJobCollectionScope
from unio_collector.scanners.analytics_ai.glue.evidence import (
    GlueJobCrawlerCostReviewEvidence,
)
from unio_collector.scanners.analytics_ai.helpers import (
    add_analytics_ai_cost_context,
    build_analytics_ai_collector,
    record_analytics_ai_execution_detail,
)
from unio_collector.scanners.analytics_ai.policy_input import read_analytics_policy_input
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.options import (
    parse_scanner_option_float,
    parse_scanner_option_int,
)
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.aws.glue.region_record import GlueRegionRecord
    from unio_collector.scanners.scanner.context import ScannerContext


class GlueJobCrawlerCostReviewCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    def collect(self, context: ScannerContext) -> GlueJobCrawlerCostReviewEvidence:  # noqa: D102
        collector = build_analytics_ai_collector(
            context,
            glue_job_run_options=self.build_job_run_collection_options(context),
        )
        records = collector.collect_glue_records()
        records = add_analytics_ai_cost_context(records, context)
        regions = collector.get_available_regions()
        record_analytics_ai_execution_detail(
            context,
            records,
            regions=regions,
        )
        self.record_job_run_coverage_notes(context, records)
        return GlueJobCrawlerCostReviewEvidence(
            records=records,
            regions=regions,
        )

    def build_job_run_collection_options(  # noqa: D102
        self,
        context: ScannerContext,
    ) -> GlueJobCollectionScope:
        scanner_id = context.definition.scanner_id
        return GlueJobCollectionScope(
            max_job_run_jobs=max(
                1,
                parse_scanner_option_int(
                    context.options.get_for_scanner(
                        scanner_id,
                        "max_job_run_jobs",
                        25,
                    ),
                ),
            ),
            max_job_runs_per_job=max(
                1,
                parse_scanner_option_int(
                    context.options.get_for_scanner(
                        scanner_id,
                        "max_job_runs_per_job",
                        10,
                    ),
                ),
            ),
            long_running_job_seconds=read_analytics_policy_input(context, "long_running_job_seconds", parse_scanner_option_int),
            high_dpu_seconds=read_analytics_policy_input(context, "high_dpu_seconds", parse_scanner_option_float),
            policy_input_source=1,
        )

    def record_job_run_coverage_notes(  # noqa: D102
        self,
        context: ScannerContext,
        records: list[GlueRegionRecord],
    ) -> None:
        for record in records:
            if not record.job_run_collection_limited:
                continue
            context.warnings.add_coverage_note(
                {
                    "scanner_id": context.definition.scanner_id,
                    "note_type": "configuration_limit",
                    "scope_area": "analytics_ai_metadata",
                    "region": record.region,
                    "summary": ("Glue job-run metadata collection was capped by scanner configuration."),
                    "reason": ("Glue job-run metadata collection was capped by scanner configuration."),
                    "config_keys": [
                        "glue-job-crawler-cost-review.max_job_run_jobs",
                        "glue-job-crawler-cost-review.max_job_runs_per_job",
                    ],
                    "jobs_checked": record.job_run_jobs_checked,
                    "job_count": record.job_count,
                    "job_run_count": record.job_run_count,
                },
            )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="GlueJobCrawlerCostReviewScanner",
            implementation_module="unio_collector.scanners.analytics_ai.glue.scanner",
        )
