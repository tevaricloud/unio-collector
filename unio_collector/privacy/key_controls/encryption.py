"""Exact encryption-baseline-review privacy binding."""

from typing import ClassVar

from unio_collector.privacy.key_controls.contract import KeyControlPrivacyContract
from unio_collector.privacy.key_controls.fields import SCANNERS


class EncryptionPrivacyContract(KeyControlPrivacyContract):
    """Bind the full explicit field contract to the registered legacy DTO."""

    scanner_id: ClassVar[str] = "encryption-baseline-review"
    fields: ClassVar = SCANNERS[scanner_id][2]
