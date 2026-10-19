"""Exact securityhub-control-summary-review privacy binding."""

from typing import ClassVar

from unio_collector.privacy.key_controls.contract import KeyControlPrivacyContract
from unio_collector.privacy.key_controls.fields import SCANNERS


class ControlSummaryPrivacyContract(KeyControlPrivacyContract):
    """Bind the full explicit field contract to the registered legacy DTO."""

    scanner_id: ClassVar[str] = "securityhub-control-summary-review"
    fields: ClassVar = SCANNERS[scanner_id][2]
