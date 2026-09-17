from __future__ import annotations

# ruff: noqa: D100,TC001
from dataclasses import dataclass

from unio_collector.scan_workflow.organization.model.account import AccountIdentity
from unio_collector.scan_workflow.organization.model.exclusion import ExcludedAccount


@dataclass(frozen=True)
class AccountSelectionResult:
    """Return selected and explicitly excluded organization accounts."""

    selected: tuple[AccountIdentity, ...]
    excluded: tuple[ExcludedAccount, ...]
