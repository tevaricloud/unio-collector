from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.iam.policy_grant_record import IamPolicyGrantRecord
    from unio_collector.scanners.iam.user_security_record import IamUserSecurityRecord


@dataclass(frozen=True)
class IamAccountSecurityEvidence:  # noqa: D101
    account_summary: dict[str, Any] = field(default_factory=dict)
    password_policy: dict[str, Any] | None = None
    users: tuple[IamUserSecurityRecord, ...] = ()
    policy_grants: tuple[IamPolicyGrantRecord, ...] = ()
    warnings: tuple[str, ...] = ()
    account_id: str = "unknown-account"
    collection_evidence_version: int = 0
    password_policy_status: str = "legacy"  # noqa: S105
