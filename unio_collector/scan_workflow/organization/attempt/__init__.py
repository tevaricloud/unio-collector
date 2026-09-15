"""Retained organization exports; internal callers use canonical contract owners."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scan_workflow.organization.attempt.cancelled_error import OrganizationAttemptCancelledError
    from unio_collector.scan_workflow.organization.attempt.report_request import OrganizationAttemptReportRequest
    from unio_collector.scan_workflow.organization.attempt.request import OrganizationAttemptRequest
    from unio_collector.scan_workflow.organization.attempt.result import OrganizationAttemptResult
    from unio_collector.scan_workflow.organization.attempt.supervisor import OrganizationAttemptSupervisor
    from unio_collector.scan_workflow.organization.attempt.timeout_error import OrganizationAttemptTimeoutError

_EXPORTS = {
    "OrganizationAttemptCancelledError": ("unio_collector.scan_workflow.organization.attempt.cancelled_error", "OrganizationAttemptCancelledError"),
    "OrganizationAttemptReportRequest": ("unio_collector.scan_workflow.organization.attempt.report_request", "OrganizationAttemptReportRequest"),
    "OrganizationAttemptRequest": ("unio_collector.scan_workflow.organization.attempt.request", "OrganizationAttemptRequest"),
    "OrganizationAttemptResult": ("unio_collector.scan_workflow.organization.attempt.result", "OrganizationAttemptResult"),
    "OrganizationAttemptSupervisor": ("unio_collector.scan_workflow.organization.attempt.supervisor", "OrganizationAttemptSupervisor"),
    "OrganizationAttemptTimeoutError": ("unio_collector.scan_workflow.organization.attempt.timeout_error", "OrganizationAttemptTimeoutError"),
}

__all__ = [
    "OrganizationAttemptCancelledError",
    "OrganizationAttemptReportRequest",
    "OrganizationAttemptRequest",
    "OrganizationAttemptResult",
    "OrganizationAttemptSupervisor",
    "OrganizationAttemptTimeoutError",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Preserve imports until an approved versioned public migration retires them."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        message = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(message) from exc
    return getattr(import_module(module_name), attribute_name)
