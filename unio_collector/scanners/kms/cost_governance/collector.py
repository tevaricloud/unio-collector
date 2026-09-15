from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext

from unio_collector.scanners.audit_cost.helpers import (
    add_audit_cost_context,
    build_audit_cost_collector,
    record_audit_cost_execution_detail,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.kms.cost_governance.evidence import KmsCostGovernanceEvidence
from unio_collector.scanners.scanner.implementation import ScannerImplementation


class KmsCostGovernanceReviewCollector(BaseUnioScanner):
    """Collect provider evidence for kms-cost-governance-review."""

    def collect(self, context: ScannerContext) -> KmsCostGovernanceEvidence:  # noqa: D102
        collector = build_audit_cost_collector(context)
        records = collector.collect_kms_records()
        records = add_audit_cost_context(records, context)
        regions = collector.get_available_regions()
        record_audit_cost_execution_detail(
            context,
            records,
            regions=regions,
        )
        return KmsCostGovernanceEvidence(
            records=records,
            regions=regions,
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="KmsCostGovernanceReviewScanner",
            implementation_module="unio_collector.scanners.kms.cost_governance.scanner",
        )
