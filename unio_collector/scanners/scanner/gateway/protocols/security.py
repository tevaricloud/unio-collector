from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.scan_workflow.runner.runtime_state import ScannerRuntimeStateView
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class ScannerSecurityGatewayRuntime(Protocol):
    """Runtime capabilities required by scanner security gateways."""

    @property
    def runtime_state(self) -> ScannerRuntimeStateView: ...  # noqa: D102

    def create_audit_context(  # noqa: D102
        self,
        definition: ScannerDefinition,
        collector: str,
    ) -> AwsAuditContext: ...
