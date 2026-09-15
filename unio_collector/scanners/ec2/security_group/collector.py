from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.security_governance.collection.regions import get_selected_or_available_regions
from unio_collector.scanners.security_governance.collection.warnings import record_context_warning
from unio_collector.scanners.security_governance.security_group.evidence import (
    SecurityGroupExposureEvidence,
)
from unio_collector.scanners.security_governance.security_group.public_rules import (
    collect_public_ingress_rules,
)

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext
    from unio_collector.scanners.security_governance.security_group.ingress_rule import (
        SecurityGroupIngressRule,
    )


from unio_collector.scanners.scanner.implementation import ScannerImplementation


class Ec2SecurityGroupExposureReviewCollector(BaseUnioScanner):
    """Collect provider evidence for ec2-security-group-exposure-review."""

    def collect(self, context: ScannerContext) -> SecurityGroupExposureEvidence:  # noqa: D102
        regions = get_selected_or_available_regions(context, "ec2")
        warnings: list[str] = []
        public_rules: list[SecurityGroupIngressRule] = []
        for region in regions:
            client = context.security.create_client(
                "ec2",
                region_name=region,
                collector_name="Ec2SecurityGroupExposureReviewScanner",
            )
            try:
                pages = client.get_paginator("describe_security_groups").paginate()
                security_groups = [item for page in pages for item in page.get("SecurityGroups", []) if isinstance(item, dict)]
            except Exception as exc:  # noqa: BLE001
                record_context_warning(
                    context,
                    warnings,
                    region,
                    "security groups",
                    exc,
                )
                continue
            for group in security_groups:
                public_rules.extend(collect_public_ingress_rules(group, region))
        for warning in warnings:
            context.warnings.add(warning)
        return SecurityGroupExposureEvidence(
            public_ingress_rules=tuple(public_rules),
            regions=tuple(regions),
            warnings=tuple(warnings),
            collection_evidence_version=1,
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="Ec2SecurityGroupExposureReviewScanner",
            implementation_module="unio_collector.scanners.ec2.security_group.exposure_scanner",
        )
