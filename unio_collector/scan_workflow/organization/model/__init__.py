"""Retained organization exports; internal callers use canonical contract owners."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scan_workflow.organization.model.account import AccountIdentity
    from unio_collector.scan_workflow.organization.model.authority import OrganizationCallerAuthority
    from unio_collector.scan_workflow.organization.model.bundle import PerAccountBundleResult
    from unio_collector.scan_workflow.organization.model.coverage import ConsolidatedCoverageSummary
    from unio_collector.scan_workflow.organization.model.exclusion import ExcludedAccount
    from unio_collector.scan_workflow.organization.model.execution import PerAccountExecutionState
    from unio_collector.scan_workflow.organization.model.failure import AccountFailure
    from unio_collector.scan_workflow.organization.model.organization import OrganizationIdentity
    from unio_collector.scan_workflow.organization.model.report import OrganizationReportResult
    from unio_collector.scan_workflow.organization.model.resume import RetryResumeState
    from unio_collector.scan_workflow.organization.model.unit import OrganizationalUnit

_EXPORTS = {
    "AccountFailure": ("unio_collector.scan_workflow.organization.model.failure", "AccountFailure"),
    "AccountIdentity": ("unio_collector.scan_workflow.organization.model.account", "AccountIdentity"),
    "ConsolidatedCoverageSummary": ("unio_collector.scan_workflow.organization.model.coverage", "ConsolidatedCoverageSummary"),
    "ExcludedAccount": ("unio_collector.scan_workflow.organization.model.exclusion", "ExcludedAccount"),
    "OrganizationCallerAuthority": ("unio_collector.scan_workflow.organization.model.authority", "OrganizationCallerAuthority"),
    "OrganizationIdentity": ("unio_collector.scan_workflow.organization.model.organization", "OrganizationIdentity"),
    "OrganizationReportResult": ("unio_collector.scan_workflow.organization.model.report", "OrganizationReportResult"),
    "OrganizationalUnit": ("unio_collector.scan_workflow.organization.model.unit", "OrganizationalUnit"),
    "PerAccountBundleResult": ("unio_collector.scan_workflow.organization.model.bundle", "PerAccountBundleResult"),
    "PerAccountExecutionState": ("unio_collector.scan_workflow.organization.model.execution", "PerAccountExecutionState"),
    "RetryResumeState": ("unio_collector.scan_workflow.organization.model.resume", "RetryResumeState"),
}

__all__ = [
    "AccountFailure",
    "AccountIdentity",
    "ConsolidatedCoverageSummary",
    "ExcludedAccount",
    "OrganizationCallerAuthority",
    "OrganizationIdentity",
    "OrganizationReportResult",
    "OrganizationalUnit",
    "PerAccountBundleResult",
    "PerAccountExecutionState",
    "RetryResumeState",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Preserve imports until an approved versioned public migration retires them."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        message = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(message) from exc
    return getattr(import_module(module_name), attribute_name)
