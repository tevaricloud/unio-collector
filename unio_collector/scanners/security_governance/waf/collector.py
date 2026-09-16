from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext

from unio_collector.aws.audit_cost.inventory import WafCostGovernanceCollectionOptions
from unio_collector.scanners.audit_cost.helpers import (
    add_audit_cost_context,
    build_audit_cost_collector,
    record_audit_cost_execution_detail,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.scanner.implementation import ScannerImplementation
from unio_collector.scanners.security_governance.waf.evidence import (
    WafCostGovernanceEvidence,
)


class WafCostGovernanceReviewCollector(BaseUnioScanner):
    """Collect provider evidence for waf-cost-governance-review."""

    def collect(self, context: ScannerContext) -> WafCostGovernanceEvidence:  # noqa: D102
        collection_options = self.build_collection_options(context)
        collector = build_audit_cost_collector(
            context,
            waf_collection_options=collection_options,
        )
        self.record_association_detail_mode_note(context, collection_options)
        records = collector.collect_waf_records()
        records = add_audit_cost_context(records, context)
        regions = collector.get_available_regions()
        record_audit_cost_execution_detail(
            context,
            records,
            regions=regions,
        )
        return WafCostGovernanceEvidence(
            records=records,
            regions=regions,
        )

    def build_collection_options(  # noqa: D102
        self,
        context: ScannerContext,
    ) -> WafCostGovernanceCollectionOptions:
        return WafCostGovernanceCollectionOptions.create(
            association_detail_mode=context.options.get(
                "association_detail_mode",
                "full",
            ),
        )

    def record_association_detail_mode_note(  # noqa: D102
        self,
        context: ScannerContext,
        collection_options: WafCostGovernanceCollectionOptions,
    ) -> None:
        if collection_options.association_detail_mode == "full":
            return
        context.warnings.add_coverage_note(
            {
                "note_type": "configuration_limit",
                "scope_area": "waf_web_acl_associations",
                "summary": (
                    "WAF web ACL association detail collection used summary mode; ListResourcesForWebACL calls were skipped for faster development scans."
                ),
                "configured_value": collection_options.association_detail_mode,
                "config_key": "waf-cost-governance-review.association_detail_mode",
                "result_scope": "current_scan",
                "impact": (
                    "Summary mode preserves web ACL, rule, visibility, and "
                    "billing context, but suppresses association-status "
                    "findings. Use full mode for client-facing WAF association "
                    "validation."
                ),
            },
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="WafCostGovernanceReviewScanner",
            implementation_module="unio_collector.scanners.security_governance.waf.scanner",
        )
