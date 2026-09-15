from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.registry.iam_requirement_sources.security.identity import SECURITY_IDENTITY_IAM_METADATA
from unio_collector.scanners.registry.iam_requirement_sources.security.posture import SECURITY_POSTURE_IAM_METADATA
from unio_collector.scanners.registry.iam_requirement_sources.security.resource import SECURITY_RESOURCE_IAM_METADATA

if TYPE_CHECKING:
    from unio_collector.scanners.registry.iam_requirements import ScannerIamMetadataDeclaration

SECURITY_GOVERNANCE_IAM_METADATA: dict[str, ScannerIamMetadataDeclaration] = {
    **SECURITY_POSTURE_IAM_METADATA,
    **SECURITY_IDENTITY_IAM_METADATA,
    **SECURITY_RESOURCE_IAM_METADATA,
}
