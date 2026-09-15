from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.audit import AwsAuditContext
from unio_collector.aws.cost_explorer import CostExplorerCollector

if TYPE_CHECKING:
    from unio_collector.core.attempt import AttemptDeadlineContract
    from unio_collector.scan_workflow.runner.runtime_state import ScannerRuntimeStateView
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class ScannerAwsCollectorFactory:
    """Create AWS collector helpers from scanner runtime state."""

    def __init__(
        self,
        runtime_state: ScannerRuntimeStateView,
        *,
        attempt: AttemptDeadlineContract | None = None,
    ) -> None:
        """Bind shared runtime state and optional scanner attempt authority."""
        self.runtime_state = runtime_state
        self.attempt = attempt

    def create_audit_context(
        self,
        definition: ScannerDefinition,
        collector: str,
    ) -> AwsAuditContext:
        """Create an audited collector context for scanner-owned collectors."""
        return AwsAuditContext(
            scanner_id=definition.scanner_id,
            collector=collector,
            allowed_api_calls=definition.aws_api_calls,
            recipient_account_id=self.runtime_state.account_id,
            attempt=self.attempt,
        )

    def create_cost_explorer_collector(
        self,
        audit_context: AwsAuditContext,
    ) -> CostExplorerCollector:
        """Create a Cost Explorer collector for scanner-owned collectors."""
        return CostExplorerCollector(
            self.runtime_state.session,
            audit_context=audit_context,
        )
