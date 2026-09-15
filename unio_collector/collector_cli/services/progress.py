from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.collector_cli.console import print_success

if TYPE_CHECKING:
    from unio_collector.scan_workflow.progress import ScanProgressEvent


class CollectorProgressReporter:
    """Minimal collector-safe scan progress reporter."""

    def __init__(
        self,
        *,
        console: Any,  # noqa: ANN401
        quiet: bool = False,
        verbose: bool = False,
        compact_progress: bool = False,
    ) -> None:
        """Store output and verbosity settings."""
        self.console = console
        self.quiet = quiet
        self.verbose = verbose
        self.compact_progress = compact_progress
        self._printed_account = False

    def print_scan_started(self, config: object, selection: object) -> None:
        """Print scan startup context."""
        if self.quiet:
            return
        print_success(self.console, "Starting Unio Collector scan")
        self.console.print(f"Provider: {getattr(config, 'provider_id', 'aws')}")
        self.console.print(f"Profile: {getattr(config, 'profile', None) or 'default'}")
        self.console.print(f"Region scope: {_describe_region_scope(config)}")
        self.console.print(
            f"Chargeable scanners: {_format_chargeable_status(config)}",
        )
        self.console.print(
            f"Enabled scanners: {len(getattr(selection, 'enabled_ids', ()))}",
        )
        self.console.print(
            f"Disabled scanners: {len(getattr(selection, 'disabled_ids', ()))}",
        )

    def handle_event(self, event: ScanProgressEvent) -> None:
        """Handle provider scan progress events."""
        if self.quiet:
            return
        if event.event_type == "identity_resolved":
            self._print_identity(event)
            return
        if event.event_type == "scanner_started" and self.verbose:
            self.console.print(f"Scanner started: {event.scanner_display_name}")
            return
        if event.event_type == "scanner_completed":
            self._print_scanner_completed(event)
            return
        if event.event_type == "phase_started" and self.verbose:
            self.console.print(f"Phase started: {event.phase_display_name}")
            return
        if event.event_type == "phase_completed" and self.verbose:
            self.console.print(f"Phase completed: {event.phase_display_name}")

    def _print_identity(self, event: ScanProgressEvent) -> None:
        if self._printed_account:
            return
        account = event.account_id or "unknown account"
        self.console.print(f"Resolved account: {account}")
        self._printed_account = True

    def _print_scanner_completed(self, event: ScanProgressEvent) -> None:
        label = event.scanner_display_name or event.scanner_id or "scanner"
        count = event.findings_count if event.findings_count is not None else 0
        status = (event.scanner_status or "unknown").replace("_", " ")
        issue_counts = self._format_issue_counts(event)
        if self.compact_progress:
            self.console.print(
                f"{status.title()}: {label} ({count} findings{issue_counts})",
            )
            return
        index = event.scanner_index
        total = event.scanner_total
        prefix = f"[{index}/{total}] " if index is not None and total is not None else ""
        self.console.print(f"{prefix}{label} {status}, {count} findings{issue_counts}")
        if self.verbose and event.message:
            self.console.print(f"  {event.message}")

    def _format_issue_counts(self, event: ScanProgressEvent) -> str:
        details: list[str] = []
        if event.error_count:
            details.append(f"errors={event.error_count}")
        if event.warning_count:
            details.append(f"warnings={event.warning_count}")
        if not details:
            return ""
        return f", {', '.join(details)}"


def _format_chargeable_status(config: object) -> str:
    if bool(getattr(config, "allow_chargeable_scanners", False)):
        return "allowed"
    return "blocked unless explicitly allowed"


def _describe_region_scope(config: object) -> str:
    describe = getattr(config, "describe_region_scope", None)
    if callable(describe):
        return str(describe())
    return "not recorded"


__all__ = ["CollectorProgressReporter"]
