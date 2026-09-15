from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.registry.iam_requirement_sources.audit_cost_governance.cloudtrail import (
    CLOUDTRAIL_IAM_METADATA,
)
from unio_collector.scanners.registry.iam_requirement_sources.audit_cost_governance.config import (
    CONFIG_IAM_METADATA,
)
from unio_collector.scanners.registry.iam_requirement_sources.audit_cost_governance.guardduty import (
    GUARDDUTY_IAM_METADATA,
)
from unio_collector.scanners.registry.iam_requirement_sources.audit_cost_governance.kms import (
    KMS_IAM_METADATA,
)
from unio_collector.scanners.registry.iam_requirement_sources.audit_cost_governance.secrets_manager import (
    SECRETS_MANAGER_IAM_METADATA,
)
from unio_collector.scanners.registry.iam_requirement_sources.audit_cost_governance.securityhub_inspector_macie import (
    SECURITYHUB_INSPECTOR_MACIE_IAM_METADATA,
)
from unio_collector.scanners.registry.iam_requirement_sources.audit_cost_governance.waf import (
    WAF_IAM_METADATA,
)

if TYPE_CHECKING:
    from unio_collector.scanners.registry.iam_requirements import (
        ScannerIamMetadataDeclaration,
    )

AUDIT_COST_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    **CLOUDTRAIL_IAM_METADATA,
    **CONFIG_IAM_METADATA,
    **GUARDDUTY_IAM_METADATA,
    **KMS_IAM_METADATA,
    **SECRETS_MANAGER_IAM_METADATA,
    **SECURITYHUB_INSPECTOR_MACIE_IAM_METADATA,
    **WAF_IAM_METADATA,
}
