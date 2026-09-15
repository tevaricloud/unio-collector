"""Retained organization exports; internal callers use canonical contract owners."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scan_workflow.organization.request.audit_role import AuditRoleConfiguration
    from unio_collector.scan_workflow.organization.request.authorization import OrganizationAuthorization
    from unio_collector.scan_workflow.organization.request.execution import OrganizationExecutionRequest
    from unio_collector.scan_workflow.organization.request.external_id import ExternalIdReference
    from unio_collector.scan_workflow.organization.request.policy import OrganizationExecutionPolicy
    from unio_collector.scan_workflow.organization.request.selection import TargetAccountSelection

_EXPORTS = {
    "AuditRoleConfiguration": ("unio_collector.scan_workflow.organization.request.audit_role", "AuditRoleConfiguration"),
    "ExternalIdReference": ("unio_collector.scan_workflow.organization.request.external_id", "ExternalIdReference"),
    "OrganizationAuthorization": ("unio_collector.scan_workflow.organization.request.authorization", "OrganizationAuthorization"),
    "OrganizationExecutionPolicy": ("unio_collector.scan_workflow.organization.request.policy", "OrganizationExecutionPolicy"),
    "OrganizationExecutionRequest": ("unio_collector.scan_workflow.organization.request.execution", "OrganizationExecutionRequest"),
    "TargetAccountSelection": ("unio_collector.scan_workflow.organization.request.selection", "TargetAccountSelection"),
}

__all__ = [
    "AuditRoleConfiguration",
    "ExternalIdReference",
    "OrganizationAuthorization",
    "OrganizationExecutionPolicy",
    "OrganizationExecutionRequest",
    "TargetAccountSelection",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Preserve imports until an approved versioned public migration retires them."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        message = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(message) from exc
    return getattr(import_module(module_name), attribute_name)
