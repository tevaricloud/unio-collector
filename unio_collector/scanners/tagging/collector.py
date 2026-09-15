from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.options import parse_scanner_option_bool
from unio_collector.scanners.scanner.implementation import ScannerImplementation
from unio_collector.scanners.tagging.association_collectors import (
    collect_auto_scaling_taggable_records,
    collect_load_balancer_taggable_records,
)
from unio_collector.scanners.tagging.evidence import TaggingEvidence
from unio_collector.scanners.tagging.record_merge import (
    build_nat_gateway_taggable_records,
    build_tagging_fast_path_disabled_note,
    build_tagging_fast_path_note,
    merge_taggable_resource_records,
)

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class MissingCostTagsCollector(BaseUnioScanner):
    """Collect provider evidence for tagging-missing-cost-tags."""

    def collect(self, context: ScannerContext) -> TaggingEvidence:  # noqa: D102
        regions = context.ec2.get_regions()
        direct_records = context.ec2.collect_records(
            collection_name="taggable_resources_without_nat_gateways",
            collect_records=(
                lambda collector: collector.collect_taggable_resources(
                    include_nat_gateways=False,
                )
            ),
        )
        nat_gateway_records = build_nat_gateway_taggable_records(
            context.network.collect_nat_gateway_records(),
        )
        records = merge_taggable_resource_records(
            list(direct_records),
            nat_gateway_records,
        )
        records = merge_taggable_resource_records(
            records,
            collect_load_balancer_taggable_records(context, records, regions),
        )
        records = merge_taggable_resource_records(
            records,
            collect_auto_scaling_taggable_records(context, records, regions),
        )
        if self.should_use_resource_groups_tagging_api(context):
            fast_path_result = context.tagging.collect_resource_groups_records(
                regions=regions,
            )
            context.data.set(
                "tagging_fast_path_summary",
                fast_path_result.convert_to_summary(),
            )
            records = merge_taggable_resource_records(
                records,
                fast_path_result.records,
            )
            context.warnings.add_coverage_note(
                build_tagging_fast_path_note(fast_path_result),
            )
        else:
            context.data.set(
                "tagging_fast_path_summary",
                {
                    "source": "resource_groups_tagging_api",
                    "status": "disabled",
                    "records_returned": 0,
                    "regions_scanned": [],
                    "errors": [],
                    "limitations": [
                        ("Resource Groups Tagging API fast-path enrichment was disabled by scanner configuration."),
                    ],
                },
            )
            context.warnings.add_coverage_note(
                build_tagging_fast_path_disabled_note(),
            )
        return TaggingEvidence(
            regions=regions,
            records=records,
            required_tags=context.options.get_required_tags(),
            analysis_inputs_version=(1 if context.options.get_scan_config_value("analysis_defaults_deferred", default=False) is True else 0),
            required_tags_supplied=(
                context.options.get_scan_config_value("analysis_defaults_deferred", default=False) is not True or bool(context.options.get_required_tags())
            ),
        )

    def should_use_resource_groups_tagging_api(  # noqa: D102
        self,
        context: ScannerContext,
    ) -> bool:
        return parse_scanner_option_bool(
            context.options.get(
                "use_resource_groups_tagging_api",
                True,
            ),
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="MissingCostTagsScanner",
            implementation_module="unio_collector.scanners.tagging.missing_cost_tags",
        )
