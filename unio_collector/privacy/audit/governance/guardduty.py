"""Exact reviewed guardduty producer privacy binding."""

from typing import ClassVar

from unio_collector.privacy.audit.governance.contract import GovernancePrivacyContract
from unio_collector.privacy.audit.governance.fields import SCANNERS


class GuardDutyPrivacyContract(GovernancePrivacyContract):
    """Bind the finite typed contract to its registered legacy evidence identity."""

    scanner_id: ClassVar[str] = "guardduty-cost-governance-review"
    fields: ClassVar = SCANNERS[scanner_id][2]
