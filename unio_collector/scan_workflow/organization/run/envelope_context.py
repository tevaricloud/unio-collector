"""Declared metadata and accepted results for an organization envelope."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.providers.aws.organization.discovery_result import OrganizationDiscoveryResult
    from unio_collector.scan_workflow.organization.run.results import OrganizationRunResults


@dataclass(frozen=True)
class OrganizationEnvelopeContext:
    """Carry explicit envelope metadata without interpreting or generating findings."""

    discovery: OrganizationDiscoveryResult
    run_id: str
    fingerprint: str
    output: Path
    results: OrganizationRunResults
    bundle_purpose: str
    analysis_state: Literal["not_analyzed", "analyzed"]
    signing_key: Path | None
    signing_key_id: str | None
