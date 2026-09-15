from __future__ import annotations

# ruff: noqa: D100
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class OrganizationAuthorization:
    """Capture explicit operator authorization and declared caller context."""

    cross_account_assessment: bool
    caller_context: Literal["management", "delegated_administrator", "operator"]
    expected_caller_account_id: str
    allow_chargeable_accounts: bool = False
    allow_chargeable_retry: bool = False
