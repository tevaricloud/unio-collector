from __future__ import annotations

# ruff: noqa: D100,TC001
from dataclasses import dataclass

from unio_collector.providers.aws.organization.selection_result import AccountSelectionResult
from unio_collector.scan_workflow.organization.model.account import AccountIdentity
from unio_collector.scan_workflow.organization.model.organization import OrganizationIdentity
from unio_collector.scan_workflow.organization.model.unit import OrganizationalUnit


@dataclass(frozen=True)
class OrganizationDiscoveryResult:
    """Return normalized discovery, selection, and optional fixture inputs."""

    organization: OrganizationIdentity
    organizational_units: tuple[OrganizationalUnit, ...]
    accounts: tuple[AccountIdentity, ...]
    selection: AccountSelectionResult
    fixture_collection_paths: dict[str, str] | None = None
