from __future__ import annotations

# ruff: noqa: D100,EM101,TC001,TRY003
from dataclasses import dataclass

from unio_collector.aws.api.call_ledger import ApiCallLedger
from unio_collector.aws.audited.session import AuditedAwsSession
from unio_collector.providers.aws.organization.role_audit import RoleAssumptionAuditRecord
from unio_collector.scan_workflow.organization.model.account import AccountIdentity


@dataclass(frozen=True)
class OrganizationAccountExecutionContext:
    """Hold isolated account credentials only in live process memory."""

    account: AccountIdentity
    session: AuditedAwsSession
    ledger: ApiCallLedger
    role_audit: RoleAssumptionAuditRecord

    def __getstate__(self) -> object:
        """Reject serialization of credential-bearing execution contexts."""
        raise TypeError("Organization account execution contexts are not serializable.")
