from __future__ import annotations  # noqa: D100

from pathlib import Path
from typing import TYPE_CHECKING, Any

from unio_collector.collector.bundle.collection_writer import (
    CollectorEvidenceBundleWriter,
)
from unio_collector.collector.execution.service import CollectorExecutionService
from unio_collector.collector.minimisation import EvidenceMinimisationOptions
from unio_collector.collector_cli.console import print_success, print_warning
from unio_collector.collector_cli.services.config import CollectorConfigResolver
from unio_collector.collector_cli.services.progress import CollectorProgressReporter
from unio_collector.collector_cli.services.progress_jsonl import CollectorJsonlProgressWriter

if TYPE_CHECKING:
    from unio_collector.scan_workflow.progress import ScanProgressEvent


class CollectorCollectService:
    """Run collector-safe evidence collection."""

    def __init__(self, console: Any) -> None:  # noqa: ANN401
        """Store the output console."""
        self.console = console

    def run(self, args: object) -> int:
        """Collect provider evidence and write an evidence bundle."""
        output_path = Path(str(getattr(args, "output", "evidence-bundle.zip")))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        config_output = output_path.parent or Path()
        resolved = CollectorConfigResolver(self.console).resolve(
            args,
            output=config_output,
        )
        progress = CollectorProgressReporter(
            console=self.console,
            quiet=bool(getattr(args, "quiet", False)),
            verbose=bool(getattr(args, "verbose", False)),
            compact_progress=bool(getattr(args, "compact_progress", False)),
        )
        progress.print_scan_started(resolved.config, resolved.selection)
        minimisation = EvidenceMinimisationOptions.from_args(args)
        jsonl_writer = CollectorJsonlProgressWriter.from_args(args)
        try:
            scan_result = CollectorExecutionService().execute(
                resolved.config,
                resolved.selection,
                lambda event: _handle_progress(progress, jsonl_writer, event),
                minimisation=minimisation,
            )
        finally:
            jsonl_writer.close()
        CollectorEvidenceBundleWriter().write(
            path=output_path,
            result=scan_result,
            minimisation=minimisation,
        )
        print_success(self.console, f"Wrote evidence bundle to {output_path}")
        if bool(getattr(args, "fail_on_degraded", False)) and scan_result.collection_status != "complete":
            print_warning(self.console, f"Collection completed with status {scan_result.collection_status}.")
            return 1
        return 0


__all__ = ["CollectorCollectService"]


def _handle_progress(
    progress: CollectorProgressReporter,
    jsonl_writer: CollectorJsonlProgressWriter,
    event: ScanProgressEvent,
) -> None:
    progress.handle_event(event)
    jsonl_writer.write(event)
