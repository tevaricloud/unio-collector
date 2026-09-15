from __future__ import annotations

# ruff: noqa: D100,D102,EM101,EM102,TC001,TRY003
import re
from pathlib import Path
from typing import Any, cast

import yaml

from unio_collector.config.organization import AwsOrganizationConfig
from unio_collector.providers.aws.organization.discovery import OrganizationDiscoveryResult
from unio_collector.providers.aws.organization.selection import OrganizationAccountSelector
from unio_collector.scan_workflow.organization.model.account import AccountIdentity, AwsAccountState
from unio_collector.scan_workflow.organization.model.authority import OrganizationCallerAuthority
from unio_collector.scan_workflow.organization.model.organization import OrganizationIdentity
from unio_collector.scan_workflow.organization.model.unit import OrganizationalUnit

_SAFE_ALIAS = re.compile(r"[^a-z0-9-]+")


class OrganizationFixtureLoader:
    """Load deterministic synthetic organization evidence without AWS sessions."""

    def load(self, path: Path, config: AwsOrganizationConfig) -> OrganizationDiscoveryResult:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Organization fixture root must be a mapping.")
        organization_raw = self._mapping(raw.get("organization"), "organization")
        management_id = str(organization_raw.get("management_account_id", ""))
        caller_id = str(organization_raw.get("caller_account_id", config.authorization.expected_caller_account_id))
        if caller_id != config.authorization.expected_caller_account_id:
            raise ValueError("Synthetic caller does not match expected_caller_account_id.")
        authority = self._authority(config, caller_id, management_id, organization_raw)
        organization = OrganizationIdentity(
            organization_id=str(organization_raw.get("id", "o-synthetic")),
            organization_arn=str(organization_raw.get("arn", "arn:aws:organizations::000000000000:organization/o-synthetic")),
            feature_set=str(organization_raw.get("feature_set", "ALL")),
            management_account_id=management_id,
            caller_account_id=caller_id,
            authority=authority,
            alias=str(organization_raw.get("alias", "synthetic-organization")),
        )
        raw_units = [self._mapping(item, "organizational_units item") for item in self._list(raw.get("organizational_units"))]
        parents = {str(item["id"]): str(item["parent_id"]) for item in raw_units}
        if len(parents) != len(raw_units):
            raise ValueError("Synthetic organization fixture contains duplicate OU IDs.")
        units = tuple(
            OrganizationalUnit(
                organizational_unit_id=str(item["id"]),
                arn=str(item.get("arn", f"arn:aws:organizations::000000000000:ou/o-synthetic/{item['id']}")),
                name=str(item.get("name", item["id"])),
                parent_id=str(item["parent_id"]),
                root_id=self._root(str(item["id"]), parents),
                ancestor_path=self._path(str(item["id"]), parents),
            )
            for item in sorted(raw_units, key=lambda value: str(value["id"]))
        )
        unit_paths = {item.organizational_unit_id: item.ancestor_path for item in units}
        aliases: set[str] = set()
        account_ids: set[str] = set()
        accounts: list[AccountIdentity] = []
        collection_paths: dict[str, str] = {}
        for index, item in enumerate(sorted(self._list(raw.get("accounts")), key=lambda value: str(value.get("id", ""))), 1):
            account = self._mapping(item, "accounts item")
            account_id = str(account["id"])
            if account_id in account_ids:
                raise ValueError("Synthetic organization fixture contains duplicate account IDs.")
            account_ids.add(account_id)
            metadata = config.account_metadata.get(account_id, {})
            alias = _SAFE_ALIAS.sub(
                "-",
                str(
                    metadata.get("alias") or account.get("alias") or f"account-{index:03d}",
                )
                .strip()
                .lower(),
            ).strip("-")
            if not alias:
                raise ValueError("Synthetic account alias does not contain any safe characters.")
            if alias in aliases:
                raise ValueError(f"Duplicate synthetic account alias: {alias}")
            aliases.add(alias)
            parent_id = str(account["parent_id"])
            labels = metadata.get("labels", {})
            accounts.append(
                AccountIdentity(
                    account_id=account_id,
                    arn=str(account.get("arn", f"arn:aws:organizations::000000000000:account/o-synthetic/{account_id}")),
                    name=str(account.get("name")) if account.get("name") else None,
                    alias=alias,
                    state=cast("AwsAccountState", str(account.get("state", "UNKNOWN"))),
                    parent_id=parent_id,
                    organizational_unit_path=unit_paths.get(parent_id, ()),
                    tags={str(key): str(value) for key, value in self._mapping(account.get("tags", {}), "tags").items()},
                    metadata={
                        str(key): (tuple(str(value) for value in values) if isinstance(values, list) else (str(values),))
                        for key, values in self._mapping(labels, "labels").items()
                    },
                    metadata_provenance="operator" if labels else "none",
                    is_management_account=account_id == management_id,
                ),
            )
            if account.get("collection_fixture"):
                fixture_path = Path(str(account["collection_fixture"]))
                if not fixture_path.is_absolute():
                    fixture_path = path.parent / fixture_path
                collection_paths[alias] = str(fixture_path.resolve())
        normalized = tuple(accounts)
        selection = OrganizationAccountSelector().select(accounts=normalized, organizational_units=units, selection=config.selection)
        return OrganizationDiscoveryResult(organization, units, normalized, selection, collection_paths)

    def _authority(self, config: AwsOrganizationConfig, caller: str, management: str, raw: dict[str, Any]) -> OrganizationCallerAuthority:
        declared = config.authorization.caller_context
        if declared == "management":
            if caller != management:
                raise ValueError("Synthetic management caller is not the management account.")
            observed = "aws_confirmed_management"
            status = "confirmed"
        elif declared == "delegated_administrator":
            principals = self._list(raw.get("delegated_service_principals"))
            if any(not isinstance(item, str) or not item.strip() for item in principals):
                raise ValueError("Synthetic delegation evidence must contain non-empty service principals.")
            services = tuple(sorted(principals))
            if not services:
                raise ValueError("Synthetic delegated-administrator fixture has no affirmative delegation evidence.")
            return OrganizationCallerAuthority(
                declared_context=declared,
                observed_authority="aws_confirmed_service_delegated_administrator",
                evidence_status="confirmed",
                delegated_service_principals=services,
                evidence_apis=("synthetic:ListDelegatedServicesForAccount",),
            )
        else:
            observed = "operator_with_observed_organizations_read_access"
            status = "observed_access"
        return OrganizationCallerAuthority(
            declared_context=declared,
            observed_authority=observed,
            evidence_status=status,
            evidence_apis=("synthetic:OrganizationsDiscovery",),
        )

    def _path(self, unit_id: str, parents: dict[str, str]) -> tuple[str, ...]:
        path: list[str] = []
        current = unit_id
        seen: set[str] = set()
        while current in parents:
            if current in seen:
                raise ValueError(f"Cycle detected in synthetic organization fixture at {current}.")
            seen.add(current)
            path.append(current)
            current = parents[current]
        return tuple(reversed(path))

    def _root(self, unit_id: str, parents: dict[str, str]) -> str:
        path = self._path(unit_id, parents)
        current = unit_id
        for _ in path:
            current = parents.get(current, current)
        return current

    def _mapping(self, value: object, key: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError(f"{key} must be a mapping.")
        return value

    def _list(self, value: object) -> list[Any]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError("Synthetic organization fixture value must be a list.")
        return value
