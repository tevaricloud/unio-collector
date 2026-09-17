from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scan_workflow.runner.runtime_state import ScannerRuntimeStateView


class ScannerCollectionDiagnostics:
    """Read scanner collection diagnostics from runtime state."""

    def __init__(self, runtime_state: ScannerRuntimeStateView) -> None:  # noqa: D107
        self.runtime_state = runtime_state

    def get_collection_diagnostics_count(self) -> int:
        """Return the current number of collection diagnostic records."""
        diagnostics = self.runtime_state.collection_diagnostics
        if diagnostics is None:
            return 0
        count = getattr(diagnostics, "count", None)
        if not callable(count):
            return 0
        value = count()
        if isinstance(value, int):
            return value
        return int(str(value))

    def build_collection_warning_messages(
        self,
        scanner_id: str,
        start_index: int,
    ) -> list[str]:
        """Return collection warning messages recorded after an index."""
        diagnostics = self.runtime_state.collection_diagnostics
        if diagnostics is None:
            return []
        build_warnings = getattr(diagnostics, "build_warning_messages_since", None)
        if not callable(build_warnings):
            return []
        messages = build_warnings(
            start_index,
            scanner_id=scanner_id,
        )
        if not isinstance(messages, list):
            return []
        return [str(message) for message in messages]

    def build_collection_runtime_summary(self) -> dict[str, Any]:
        """Return a safe collection runtime summary from diagnostics."""
        diagnostics = self.runtime_state.collection_diagnostics
        if diagnostics is None:
            return {}
        convert_to_summary = getattr(diagnostics, "convert_to_summary", None)
        if not callable(convert_to_summary):
            return {}
        summary = convert_to_summary()
        return summary if isinstance(summary, dict) else {}
