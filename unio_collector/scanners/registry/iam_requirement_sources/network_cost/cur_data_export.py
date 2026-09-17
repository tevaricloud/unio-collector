from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

CUR_DATA_EXPORT_ATTRIBUTION_EVIDENCE = (
    "CUR line item",
    "Billing resource",
    "Cost allocation tag",
)

CUR_DATA_EXPORT_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "cur-data-export-attribution": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "s3:GetObject",
                "required",
                "CUR/Data Export attribution requires s3:GetObject to collect read-only CUR line item, Billing resource, Cost allocation tag evidence.",
                chargeable=False,
                evidence_categories=CUR_DATA_EXPORT_ATTRIBUTION_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="s3:GetObject is rendered with Resource='*' because the scanner IAM metadata does not declare safe resource-level "
                "constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
