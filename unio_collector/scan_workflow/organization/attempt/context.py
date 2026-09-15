"""Parent-only inputs shared by bounded organization account attempts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.aws.audited.session import AuditedAwsSession
    from unio_collector.collector.config.protocol import CollectionConfigProtocol
    from unio_collector.collector.minimisation import EvidenceMinimisationOptions
    from unio_collector.config.organization import AwsOrganizationConfig
    from unio_collector.scan_workflow.organization.model.account import AccountIdentity
    from unio_collector.scanners.selection import ScannerSelection


@dataclass(frozen=True)
class OrganizationAccountAttemptContext:
    """Carry parent authority without serializing its session or checkpoint lock."""

    account: AccountIdentity
    management_session: AuditedAwsSession | None
    organization_config: AwsOrganizationConfig
    scan_config: CollectionConfigProtocol
    scanner_selection: ScannerSelection
    bundles_dir: Path
    staging_dir: Path
    minimisation: EvidenceMinimisationOptions | None
    run_id: str
    state: dict[str, Any]
    state_path: Path
    state_lock: Any
