"""A validated account bundle and its persisted commit checkpoint."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scan_workflow.organization.model.bundle import PerAccountBundleResult


@dataclass(frozen=True)
class CommittedAccountBundle:
    """Retain the bundle outcome while an optional completion operation runs."""

    bundle_result: PerAccountBundleResult
    checkpoint_state: dict[str, Any]
