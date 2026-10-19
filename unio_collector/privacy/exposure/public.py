"""Exact public-service-exposure-review producer privacy binding."""

from typing import ClassVar

from unio_collector.privacy.exposure.contract import ExposurePrivacyContract
from unio_collector.privacy.exposure.fields import SCANNERS


class PublicExposurePrivacyContract(ExposurePrivacyContract):
    """Bind the emitted DTO to its enumerated AWS scanner identity."""

    scanner_id: ClassVar[str] = "public-service-exposure-review"
    fields: ClassVar = SCANNERS[scanner_id][2]
