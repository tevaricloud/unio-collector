"""Exact reviewed waf producer privacy binding."""

from typing import ClassVar

from unio_collector.privacy.audit.governance.contract import GovernancePrivacyContract
from unio_collector.privacy.audit.governance.fields import SCANNERS


class WafPrivacyContract(GovernancePrivacyContract):
    """Bind the finite typed contract to its registered legacy evidence identity."""

    scanner_id: ClassVar[str] = "waf-cost-governance-review"
    fields: ClassVar = SCANNERS[scanner_id][2]
