from __future__ import annotations

from typing import TYPE_CHECKING

from unio_collector.providers.aws.organization.selection_result import AccountSelectionResult

# ruff: noqa: D100, D102, FBT001, FBT003
from unio_collector.scan_workflow.organization.model.exclusion import ExcludedAccount

if TYPE_CHECKING:
    from unio_collector.scan_workflow.organization.model.account import AccountIdentity
    from unio_collector.scan_workflow.organization.model.unit import OrganizationalUnit
    from unio_collector.scan_workflow.organization.request.selection import TargetAccountSelection


class OrganizationAccountSelector:
    """Apply explicit selectors deterministically and fail closed."""

    def select(
        self,
        *,
        accounts: tuple[AccountIdentity, ...],
        organizational_units: tuple[OrganizationalUnit, ...],
        selection: TargetAccountSelection,
    ) -> AccountSelectionResult:
        by_id = {account.account_id: account for account in accounts}
        known_ous = {item.organizational_unit_id for item in organizational_units}
        missing_accounts = sorted(set(selection.account_ids) - set(by_id))
        if missing_accounts:
            raise ValueError("Selected AWS account IDs were not discovered: " + ", ".join(missing_accounts))
        requested_ous = set(selection.organizational_unit_ids) | set(selection.denied_organizational_unit_ids)
        missing_ous = sorted(requested_ous - known_ous)
        if missing_ous:
            raise ValueError("Selected AWS Organizations OU IDs were not discovered: " + ", ".join(missing_ous))

        selected: list[AccountIdentity] = []
        excluded: list[ExcludedAccount] = []
        for account in sorted(accounts, key=lambda item: item.account_id):
            positive = self._positive_match(account, selection)
            exclusion = self._exclusion(account, selection, positive)
            if exclusion is not None:
                excluded.append(exclusion)
            else:
                selected.append(account)
        return AccountSelectionResult(tuple(selected), tuple(excluded))

    def _positive_match(self, account: AccountIdentity, selection: TargetAccountSelection) -> bool:
        if selection.all_active_accounts:
            return True
        if account.account_id in selection.account_ids:
            return True
        if self._ou_match(account, set(selection.organizational_unit_ids), selection.include_descendants):
            return True
        if selection.account_tag_selectors and all(account.tags.get(key) in values for key, values in selection.account_tag_selectors):
            return True
        return bool(
            selection.metadata_selectors and all(bool(set(account.metadata.get(key, ())) & set(values)) for key, values in selection.metadata_selectors)
        )

    def _exclusion(
        self,
        account: AccountIdentity,
        selection: TargetAccountSelection,
        positive: bool,
    ) -> ExcludedAccount | None:
        if account.account_id in selection.denied_account_ids:
            return self._excluded(account, "account_denied", "The account ID is explicitly denied.")
        if self._ou_match(account, set(selection.denied_organizational_unit_ids), True):
            return self._excluded(account, "ou_denied", "The account belongs to an explicitly denied OU.")
        if not positive:
            if selection.account_tag_selectors and account.tag_evidence_status == "unavailable":
                return self._excluded(
                    account,
                    "selector_evidence_unavailable",
                    "Required account-tag evidence was unavailable; selection failed closed.",
                )
            if selection.metadata_selectors and not account.metadata:
                return self._excluded(
                    account,
                    "selector_evidence_unavailable",
                    "Required operator metadata was not supplied; selection failed closed.",
                )
            return self._excluded(account, "not_selected", "No positive selector matched the account.")
        if account.state != "ACTIVE":
            return self._excluded(account, "account_not_active", f"AWS account state is {account.state}.")
        if account.is_management_account and not (selection.include_management_account and account.account_id in selection.account_ids):
            return self._excluded(
                account,
                "management_account_not_authorized",
                "Management account assessment requires exact allowlisting and explicit consent.",
            )
        return None

    def _ou_match(self, account: AccountIdentity, ou_ids: set[str], descendants: bool) -> bool:
        if not ou_ids:
            return False
        if descendants:
            return bool(set(account.organizational_unit_path) & ou_ids)
        return account.parent_id in ou_ids

    def _excluded(self, account: AccountIdentity, code: str, explanation: str) -> ExcludedAccount:
        return ExcludedAccount(
            account_reference=account.alias,
            state=account.state,
            exclusion_code=code,
            explanation=explanation,
        )
