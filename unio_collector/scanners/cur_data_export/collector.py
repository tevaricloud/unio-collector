from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.cur.collection.projection import project_billing_evidence
from unio_collector.aws.cur.collection.reader import CurBillingReader
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.cur_data_export.evidence import CurDataExportEvidence
from unio_collector.scanners.cur_data_export.source import build_cur_s3_object_fetcher
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class CurDataExportAttributionCollector(BaseUnioScanner):
    """Collect provider evidence for cur-data-export-attribution."""

    def collect(self, context: ScannerContext) -> CurDataExportEvidence:  # noqa: D102
        config = context.options.get_config()
        result = CurBillingReader(
            config.cur_paths,
            s3_object_fetcher=build_cur_s3_object_fetcher(context),
        ).read_observations(config.scan_period, group_by_tags=config.cost_grouping_tags)
        return CurDataExportEvidence(
            collection_evidence_version=1,
            billing_facts=project_billing_evidence(result, paths_supplied=bool(config.cur_paths)),
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="CurDataExportAttributionScanner",
            implementation_module="unio_collector.scanners.cur_data_export.attribution_scanner",
        )
