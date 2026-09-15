from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.cloudfront import CloudFrontInventoryCollector
from unio_collector.aws.cloudfront.helpers import (
    normalize_cloudfront_invalidation_detail_mode,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.network.cloudfront_origin.evidence import (
    CloudFrontOriginCostReviewEvidence,
)
from unio_collector.scanners.network.cloudfront_origin.helpers import (
    build_cloudfront_execution_detail_note,
)
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class CloudFrontOriginCostReviewCollector(BaseUnioScanner):
    """Collect network evidence without running finding interpretation."""

    def collect(self, context: ScannerContext) -> CloudFrontOriginCostReviewEvidence:  # noqa: D102
        collector = CloudFrontInventoryCollector(
            context.security.session,
            account_id=context.security.account_id,
            audit_context=context.security.create_audit_context(
                "CloudFrontInventoryCollector",
            ),
            scan_period=context.options.get_scan_period(),
            collect_metrics=bool(
                context.options.get_scan_config_value(
                    "allow_chargeable_scanners",
                    default=False,
                ),
            ),
            invalidation_detail_mode=normalize_cloudfront_invalidation_detail_mode(
                context.options.get(
                    "invalidation_detail_mode",
                    "full",
                ),
            ),
        )
        record = collector.collect_distribution_record()
        context.warnings.add_coverage_note(
            build_cloudfront_execution_detail_note(record),
        )
        self.record_invalidation_detail_note(context, collector)
        return CloudFrontOriginCostReviewEvidence(
            records=[record],
        )

    def record_invalidation_detail_note(  # noqa: D102
        self,
        context: ScannerContext,
        collector: CloudFrontInventoryCollector,
    ) -> None:
        if collector.invalidation_detail_mode == "full":
            return
        context.warnings.add_coverage_note(
            {
                "note_type": "configuration_limit",
                "scope_area": "cloudfront_invalidations",
                "summary": ("CloudFront invalidation detail collection used summary mode; ListInvalidations calls were skipped for faster development scans."),
                "configured_value": collector.invalidation_detail_mode,
                "config_key": ("cloudfront-origin-cost-review.invalidation_detail_mode"),
                "result_scope": "current_scan",
                "impact": (
                    "Distribution, origin, cache behavior, logging, tag, and "
                    "optional metric checks still run, but invalidation batch, "
                    "path, wildcard, and recency signals are not confirmed in "
                    "this mode."
                ),
            },
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="CloudFrontOriginCostReviewScanner",
            implementation_module="unio_collector.scanners.network.cloudfront_origin.scanner",
        )
