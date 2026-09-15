"""Parent-owned inputs for one organization bundle commit."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.scan_workflow.organization.attempt.result import OrganizationAttemptResult


@dataclass(frozen=True)
class OrganizationBundleCommitRequest:
    """Keep staging, generation and checkpoint authority in one runtime object."""

    alias: str
    child_result: OrganizationAttemptResult
    attempt_root: Path
    bundles_dir: Path
    attempt: int
    state: dict[str, Any]
    state_path: Path
    state_lock: Any
