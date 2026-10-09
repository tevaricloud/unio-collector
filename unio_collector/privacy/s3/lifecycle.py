"""Identity-bound closed lifecycle evidence privacy."""

from __future__ import annotations

from typing import ClassVar

from unio_collector.privacy.s3.base import S3PrivacyContract
from unio_collector.privacy.s3.fields import LIFECYCLE, Spec


class S3LifecyclePrivacyContract(S3PrivacyContract):
    """Protect only the explicitly declared producer field inventory."""

    scanners: ClassVar[dict[str, tuple[str, str]]] = {
        "s3-lifecycle-cost-review": ("lifecycle.evidence", "S3LifecycleEvidence"),
        "s3-versioning-and-replication-review": ("lifecycle.evidence", "S3LifecycleEvidence"),
    }
    fields: ClassVar[dict[str, Spec]] = LIFECYCLE
