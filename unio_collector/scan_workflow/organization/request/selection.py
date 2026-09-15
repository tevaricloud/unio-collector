from __future__ import annotations

# ruff: noqa: D100
from dataclasses import dataclass


@dataclass(frozen=True)
class TargetAccountSelection:
    """Describe explicit positive and negative account selectors."""

    account_ids: tuple[str, ...] = ()
    organizational_unit_ids: tuple[str, ...] = ()
    account_tag_selectors: tuple[tuple[str, tuple[str, ...]], ...] = ()
    metadata_selectors: tuple[tuple[str, tuple[str, ...]], ...] = ()
    denied_account_ids: tuple[str, ...] = ()
    denied_organizational_unit_ids: tuple[str, ...] = ()
    include_descendants: bool = False
    all_active_accounts: bool = False
    include_management_account: bool = False

    @property
    def has_positive_selector(self) -> bool:
        """Return whether assessment scope has an affirmative selector."""
        return bool(self.account_ids or self.organizational_unit_ids or self.account_tag_selectors or self.metadata_selectors or self.all_active_accounts)
