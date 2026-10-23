"""Exact root-account-recovery-advisory producer privacy binding."""

from typing import ClassVar

from unio_collector.privacy.exposure.contract import ExposurePrivacyContract
from unio_collector.privacy.exposure.fields import SCANNERS


class RootRecoveryPrivacyContract(ExposurePrivacyContract):
    """Bind the emitted DTO to its enumerated AWS scanner identity."""

    scanner_id: ClassVar[str] = "root-account-recovery-advisory"
    fields: ClassVar = SCANNERS[scanner_id][2]
