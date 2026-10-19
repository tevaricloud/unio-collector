"""Identity-bound closed public access evidence privacy."""

from __future__ import annotations

from typing import ClassVar

from unio_collector.privacy.s3.base import S3PrivacyContract
from unio_collector.privacy.s3.fields import PUBLIC, Spec


class S3PublicAccessPrivacyContract(S3PrivacyContract):
    """Protect only the explicitly declared producer field inventory."""

    scanners: ClassVar[dict[str, tuple[str, str]]] = {"s3-public-access-security-review": ("public_access.evidence", "S3PublicAccessEvidence")}
    fields: ClassVar[dict[str, Spec]] = PUBLIC
