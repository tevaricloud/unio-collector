from __future__ import annotations  # noqa: D100

from unio_collector.scanners.registry.iam_requirements import (
    ScannerIamMetadataDeclaration,
)
from unio_collector.scanners.scanner.permission import ScannerIamRequirement as Req

DATA_TRANSFER_COST_REVIEW_EVIDENCE = ("Cost Explorer usage type",)

DATA_TRANSFER_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    "data-transfer-cost-review": ScannerIamMetadataDeclaration(
        iam_requirements=(
            Req(
                "ce:GetCostAndUsage",
                "required",
                "Data transfer cost review requires ce:GetCostAndUsage to collect read-only Cost Explorer usage type evidence.",
                chargeable=False,
                evidence_categories=DATA_TRANSFER_COST_REVIEW_EVIDENCE,
                resource_scope="wildcard_required",
                resource_scope_reason="ce:GetCostAndUsage is rendered with Resource='*' because the scanner IAM metadata does not declare safe "
                "resource-level constraints for this action.",
                conditional_on=None,
            ),
        ),
    ),
}
