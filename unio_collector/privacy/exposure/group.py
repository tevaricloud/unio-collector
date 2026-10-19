"""Exact ec2-security-group-exposure-review producer privacy binding."""

from typing import ClassVar

from unio_collector.privacy.exposure.contract import ExposurePrivacyContract
from unio_collector.privacy.exposure.fields import SCANNERS


class SecurityGroupPrivacyContract(ExposurePrivacyContract):
    """Bind the emitted DTO to its enumerated AWS scanner identity."""

    scanner_id: ClassVar[str] = "ec2-security-group-exposure-review"
    fields: ClassVar = SCANNERS[scanner_id][2]

    def is_public_port(self, suffix: str, value: object) -> bool:
        """Recognize only the two typed bounded port controls in this exact DTO."""
        spec = self.fields.get(suffix)
        return spec is not None and spec[:2] == ("port", "safe_metadata") and self._valid(value, "port", nullable=False)
