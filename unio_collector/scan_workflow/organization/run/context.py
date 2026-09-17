"""Inputs for parent-supervised bounded organization scheduling."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.config.organization import AwsOrganizationConfig
    from unio_collector.scan_workflow.organization.model.account import AccountIdentity
    from unio_collector.scan_workflow.organization.run.results import OrganizationRunResults


@dataclass(frozen=True)
class OrganizationScheduleContext:
    """Bind pending accounts to the existing checkpoint and output authority."""

    pending: tuple[AccountIdentity, ...]
    organization_config: AwsOrganizationConfig
    bundles_dir: Path
    state: dict[str, Any]
    state_path: Path
    state_lock: Any
    results: OrganizationRunResults
