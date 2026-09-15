"""Lazy compatibility surface for provider application execution contracts."""

from importlib import import_module
from typing import TYPE_CHECKING, Any

from unio_collector.scan_workflow.provider_execution.executor import (
    ProviderScanExecutorProtocol,
)

if TYPE_CHECKING:
    from unio_collector.scan_workflow.provider_execution.contract import ScanWorkflowResult
    from unio_collector.scan_workflow.provider_execution.handler_service import ProviderScopedScannerExecutionService
    from unio_collector.scan_workflow.provider_execution.registration import ProviderScopedScannerRegistration
    from unio_collector.scan_workflow.provider_execution.result import ProviderScanWorkflowResult
    from unio_collector.scan_workflow.provider_execution.scoped_result import ProviderScopedScannerExecution

__all__ = [
    "ProviderScanExecutorProtocol",
    "ProviderScanWorkflowResult",
    "ProviderScopedScannerExecution",
    "ProviderScopedScannerExecutionService",
    "ProviderScopedScannerRegistration",
    "ScanWorkflowResult",
]


_EXPORTS: dict[str, tuple[str, str]] = {
    "ScanWorkflowResult": ("unio_collector.scan_workflow.provider_execution.contract", "ScanWorkflowResult"),
    "ProviderScopedScannerExecutionService": ("unio_collector.scan_workflow.provider_execution.handler_service", "ProviderScopedScannerExecutionService"),
    "ProviderScopedScannerRegistration": ("unio_collector.scan_workflow.provider_execution.registration", "ProviderScopedScannerRegistration"),
    "ProviderScanWorkflowResult": ("unio_collector.scan_workflow.provider_execution.result", "ProviderScanWorkflowResult"),
    "ProviderScopedScannerExecution": ("unio_collector.scan_workflow.provider_execution.scoped_result", "ProviderScopedScannerExecution"),
}


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve a historical application export from its canonical module."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
