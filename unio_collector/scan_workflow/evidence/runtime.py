from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.cost_explorer import CostExplorerCollector
    from unio_collector.scan_workflow.runner.runtime_state import ScannerRuntimeStateView
    from unio_collector.scan_workflow.scanner.attempt.context import ScannerAttemptContext
    from unio_collector.scan_workflow.scanner.runtime.cancellation import (
        ScannerCancellationToken,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class ScannerEvidenceRuntime(Protocol):
    """Narrow runtime contract required by evidence collection collaborators."""

    @property
    def runtime_state(self) -> ScannerRuntimeStateView: ...  # noqa: D102

    @property
    def shared_evidence_prefetches(self) -> list[dict[str, Any]]: ...  # noqa: D102

    @property
    def cancellation_token(self) -> ScannerCancellationToken: ...  # noqa: D102

    @property
    def active_attempt(self) -> ScannerAttemptContext | None: ...  # noqa: D102

    def create_audit_context(  # noqa: D102
        self,
        definition: ScannerDefinition,
        collector: str,
    ) -> AwsAuditContext: ...

    def create_cost_explorer_collector(  # noqa: D102
        self,
        audit_context: AwsAuditContext,
    ) -> CostExplorerCollector: ...

    def add_scanner_coverage_note(  # noqa: D102
        self,
        scanner_id: str,
        note: dict[str, Any],
    ) -> None: ...
