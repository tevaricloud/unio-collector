"""Exact privacy binding for cloudtrail-security-posture-review."""

from __future__ import annotations

from typing import ClassVar

from unio_collector.privacy.audit.contract import AuditPrivacyContract
from unio_collector.privacy.audit.fields import TRAIL_SECURITY


class TrailSecurityPrivacyContract(AuditPrivacyContract):
    """Keep this actual producer's fields distinct from adjacent schemas."""

    scanner_id: ClassVar[str] = "cloudtrail-security-posture-review"
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = TRAIL_SECURITY
