"""Exact aws-security-service-coverage-review privacy binding."""

from typing import ClassVar

from unio_collector.privacy.identity.contract import IdentityPrivacyContract
from unio_collector.privacy.identity.fields import SCANNERS


class SecurityCoveragePrivacyContract(IdentityPrivacyContract):
    """Bind the explicit DTO contract to its registered AWS scanner identity."""

    scanner_id: ClassVar[str] = "aws-security-service-coverage-review"
    fields: ClassVar = SCANNERS[scanner_id][2]
