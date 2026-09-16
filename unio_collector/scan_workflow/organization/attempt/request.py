"""Serializable request for one isolated organization account attempt."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.collector.config.protocol import CollectionConfigProtocol
    from unio_collector.collector.minimisation import EvidenceMinimisationOptions
    from unio_collector.config.organization import AwsOrganizationConfig
    from unio_collector.scan_workflow.organization.model.account import AccountIdentity
    from unio_collector.scanners.selection import ScannerSelection


@dataclass(frozen=True)
class OrganizationAttemptRequest[ReportInputT]:
    """Credential-free inputs reconstructed within a spawned child."""

    account: AccountIdentity
    organization_config: AwsOrganizationConfig
    scan_config: CollectionConfigProtocol
    scanner_selection: ScannerSelection
    staging_root: Path
    run_id: str
    attempt: int
    operation: Literal["collect", "scan"] = "collect"
    fixture_path: Path | None = None
    minimisation: EvidenceMinimisationOptions | None = None
    report_request: ReportInputT | None = None


__all__ = ["OrganizationAttemptRequest"]
