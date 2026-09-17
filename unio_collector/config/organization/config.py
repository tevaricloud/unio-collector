from __future__ import annotations

# ruff: noqa: D100,TC001
from dataclasses import dataclass

from unio_collector.scan_workflow.organization.request.audit_role import AuditRoleConfiguration
from unio_collector.scan_workflow.organization.request.authorization import OrganizationAuthorization
from unio_collector.scan_workflow.organization.request.policy import OrganizationExecutionPolicy
from unio_collector.scan_workflow.organization.request.selection import TargetAccountSelection


@dataclass(frozen=True)
class AwsOrganizationConfig:
    """Hold validated AWS organization orchestration configuration."""

    authorization: OrganizationAuthorization
    selection: TargetAccountSelection
    audit_role: AuditRoleConfiguration
    execution: OrganizationExecutionPolicy
    account_metadata: dict[str, dict[str, object]]
