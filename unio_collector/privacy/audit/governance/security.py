"""Exact reviewed security producer privacy binding."""

from typing import ClassVar

from unio_collector.privacy.audit.governance.contract import GovernancePrivacyContract
from unio_collector.privacy.audit.governance.fields import SCANNERS


class SecurityServicesPrivacyContract(GovernancePrivacyContract):
    """Bind the finite typed contract to its registered legacy evidence identity."""

    scanner_id: ClassVar[str] = "securityhub-inspector-macie-cost-review"
    fields: ClassVar = SCANNERS[scanner_id][2]
