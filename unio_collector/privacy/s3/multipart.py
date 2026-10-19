"""Identity-bound closed multipart evidence privacy."""

from __future__ import annotations

from typing import ClassVar

from unio_collector.privacy.s3.base import S3PrivacyContract
from unio_collector.privacy.s3.fields import MULTIPART, Spec


class S3MultipartPrivacyContract(S3PrivacyContract):
    """Protect only the explicitly declared producer field inventory."""

    scanners: ClassVar[dict[str, tuple[str, str]]] = {"s3-incomplete-multipart-review": ("incomplete_multipart.evidence", "S3MultipartEvidence")}
    fields: ClassVar[dict[str, Spec]] = MULTIPART
