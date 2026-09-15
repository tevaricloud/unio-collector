"""Parent-owned organization outcomes collected across account attempts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.scan_workflow.organization.model.bundle import PerAccountBundleResult
    from unio_collector.scan_workflow.organization.model.failure import AccountFailure


@dataclass
class OrganizationRunResults:
    """Retain accepted bundles, sanitized failures and cancellation accounting."""

    children: dict[str, Path] = field(default_factory=dict)
    bundle_results: dict[str, PerAccountBundleResult] = field(default_factory=dict)
    failures: dict[str, AccountFailure] = field(default_factory=dict)
    audits: list[dict[str, object]] = field(default_factory=list)
    cancelled: bool = False
    cancelled_count: int = 0
