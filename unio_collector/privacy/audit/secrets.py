"""Exact privacy binding for secrets-manager-cost-governance-review."""

from __future__ import annotations

from typing import ClassVar

from unio_collector.privacy.audit.contract import AuditPrivacyContract
from unio_collector.privacy.audit.fields import SECRETS


class SecretsPrivacyContract(AuditPrivacyContract):
    """Keep this actual producer's fields distinct from adjacent schemas."""

    scanner_id: ClassVar[str] = "secrets-manager-cost-governance-review"
    fields: ClassVar[dict[str, tuple[str, str, bool]]] = SECRETS
