from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext

from unio_collector.aws.audit_cost.inventory import ConfigCostGovernanceCollectionOptions
from unio_collector.scanners.audit_cost.helpers import (
    add_audit_cost_context,
    build_audit_cost_collector,
    record_audit_cost_execution_detail,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.config.cost_governance.evidence import (
    ConfigCostGovernanceEvidence,
)
from unio_collector.scanners.scanner.implementation import ScannerImplementation


class ConfigCostGovernanceReviewCollector(BaseUnioScanner):
    """Collect provider evidence for config-cost-governance-review."""

    def collect(self, context: ScannerContext) -> ConfigCostGovernanceEvidence:  # noqa: D102
        collection_options = self.build_collection_options(context)
        collector = build_audit_cost_collector(
            context,
            config_collection_options=collection_options,
        )
        self.record_rule_detail_mode_note(context, collection_options)
        records = collector.collect_config_records()
        records = add_audit_cost_context(records, context)
        regions = collector.get_available_regions()
        record_audit_cost_execution_detail(
            context,
            records,
            regions=regions,
        )
        return ConfigCostGovernanceEvidence(
            records=records,
            regions=regions,
        )

    def build_collection_options(  # noqa: D102
        self,
        context: ScannerContext,
    ) -> ConfigCostGovernanceCollectionOptions:
        return ConfigCostGovernanceCollectionOptions.create(
            rule_detail_mode=context.options.get(
                "rule_detail_mode",
                "full",
            ),
        )

    def record_rule_detail_mode_note(  # noqa: D102
        self,
        context: ScannerContext,
        collection_options: ConfigCostGovernanceCollectionOptions,
    ) -> None:
        if collection_options.rule_detail_mode == "full":
            return
        context.warnings.add_coverage_note(
            {
                "note_type": "configuration_limit",
                "scope_area": "config_rule_metadata",
                "summary": (
                    "AWS Config rule and conformance-pack detail collection "
                    "used summary mode; DescribeConfigRules and "
                    "DescribeConformancePacks calls were skipped for faster "
                    "development scans."
                ),
                "configured_value": collection_options.rule_detail_mode,
                "config_key": "config-cost-governance-review.rule_detail_mode",
                "result_scope": "current_scan",
                "impact": (
                    "Summary mode preserves recorder, status, and delivery "
                    "channel context, but suppresses Config rule-volume and "
                    "conformance-pack findings. Use full mode for client-facing "
                    "rule governance coverage."
                ),
            },
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="ConfigCostGovernanceReviewScanner",
            implementation_module="unio_collector.scanners.config.cost_governance.scanner",
        )
