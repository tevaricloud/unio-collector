from __future__ import annotations  # noqa: D104

from unio_collector.scanners.registry.definitions.security.governance.coverage import (
    SECURITY_GOVERNANCE_COVERAGE_SCANNERS,
)
from unio_collector.scanners.registry.definitions.security.governance.encryption import (
    SECURITY_GOVERNANCE_ENCRYPTION_SCANNERS,
)
from unio_collector.scanners.registry.definitions.security.governance.exposure import (
    SECURITY_GOVERNANCE_EXPOSURE_SCANNERS,
)
from unio_collector.scanners.registry.definitions.security.governance.identity import (
    SECURITY_GOVERNANCE_IDENTITY_SCANNERS,
)
from unio_collector.scanners.registry.source import ScannerDefinitionSource

SECURITY_GOVERNANCE_SCANNERS = {
    **SECURITY_GOVERNANCE_IDENTITY_SCANNERS,
    **SECURITY_GOVERNANCE_EXPOSURE_SCANNERS,
    **SECURITY_GOVERNANCE_COVERAGE_SCANNERS,
    **SECURITY_GOVERNANCE_ENCRYPTION_SCANNERS,
}

SECURITY_GOVERNANCE_SCANNER_DEFINITION_SOURCE = ScannerDefinitionSource(
    "security_governance",
    SECURITY_GOVERNANCE_SCANNERS,
)


__all__ = [
    "SECURITY_GOVERNANCE_COVERAGE_SCANNERS",
    "SECURITY_GOVERNANCE_ENCRYPTION_SCANNERS",
    "SECURITY_GOVERNANCE_EXPOSURE_SCANNERS",
    "SECURITY_GOVERNANCE_IDENTITY_SCANNERS",
    "SECURITY_GOVERNANCE_SCANNERS",
    "SECURITY_GOVERNANCE_SCANNER_DEFINITION_SOURCE",
]
