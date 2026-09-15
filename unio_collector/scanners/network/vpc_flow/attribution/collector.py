from __future__ import annotations  # noqa: D100

import sys
from typing import TYPE_CHECKING, Any, cast

from unio_collector.aws.flow.collector import VpcFlowLogCollector
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.network.vpc_flow.attribution.evidence import (
    VpcFlowLogAttributionEvidence,
)
from unio_collector.scanners.network.vpc_flow.query_options import VpcFlowQueryOptions
from unio_collector.scanners.options import (
    parse_scanner_option_float,
    parse_scanner_option_int,
)
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class VpcFlowLogAttributionCollector(BaseUnioScanner):
    """Collect network evidence without running finding interpretation."""

    def collect(self, context: ScannerContext) -> VpcFlowLogAttributionEvidence:  # noqa: D102
        query_options = self._build_query_options(context)
        collector = context.security.create_regional_inventory_collector(
            self._get_collector_type(),
            collector_name="VpcFlowLogCollector",
        )
        records, metadata = collector.collect_attribution(
            context.options.get_scan_period(),
            max_log_groups_per_region=query_options.max_log_groups,
            query_limit=query_options.query_limit,
            max_query_polls=query_options.max_query_polls,
            poll_seconds=query_options.poll_seconds,
            query_timeout_seconds=query_options.query_timeout_seconds,
        )
        return VpcFlowLogAttributionEvidence(
            collector=None,
            records=records,
            metadata=metadata,
            query_options=query_options,
            regions=collector.get_available_regions(),
            scan_period=context.options.get_scan_period(),
        )

    def _get_collector_type(self) -> type[Any]:
        network_facade = sys.modules.get("unio_collector.scanners.network")
        collector_type = getattr(network_facade, "VpcFlowLogCollector", VpcFlowLogCollector) if network_facade is not None else VpcFlowLogCollector
        return cast("type[Any]", collector_type)

    def _build_query_options(self, context: ScannerContext) -> VpcFlowQueryOptions:
        max_log_groups = parse_scanner_option_int(
            context.options.get(
                "max_log_groups_per_region",
                3,
            ),
        )
        query_limit = parse_scanner_option_int(
            context.options.get(
                "query_limit",
                50,
            ),
        )
        max_query_polls = parse_scanner_option_int(
            context.options.get(
                "max_query_polls",
                12,
            ),
        )
        poll_seconds = parse_scanner_option_float(
            context.options.get(
                "poll_seconds",
                1.0,
            ),
        )
        configured_timeout = context.options.get(
            "query_timeout_seconds",
            None,
        )
        max_log_groups = max(1, max_log_groups)
        query_limit = max(1, query_limit)
        max_query_polls = max(1, max_query_polls)
        poll_seconds = max(0.1, poll_seconds)
        legacy_timeout = max_query_polls * poll_seconds
        query_timeout_seconds = max(1.0, parse_scanner_option_float(configured_timeout)) if configured_timeout is not None else max(120.0, legacy_timeout)
        return VpcFlowQueryOptions(
            max_log_groups=max_log_groups,
            query_limit=query_limit,
            max_query_polls=max_query_polls,
            poll_seconds=poll_seconds,
            query_timeout_seconds=query_timeout_seconds,
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="VpcFlowLogAttributionScanner",
            implementation_module="unio_collector.scanners.network.vpc_flow.attribution.scanner",
        )
