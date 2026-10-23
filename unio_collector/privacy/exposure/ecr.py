"""Exact ecr-image-scan-posture-review producer privacy binding."""

from typing import ClassVar

from unio_collector.privacy.exposure.contract import ExposurePrivacyContract
from unio_collector.privacy.exposure.fields import SCANNERS


class EcrPrivacyContract(ExposurePrivacyContract):
    """Bind the emitted DTO to its enumerated AWS scanner identity."""

    scanner_id: ClassVar[str] = "ecr-image-scan-posture-review"
    fields: ClassVar = SCANNERS[scanner_id][2]
