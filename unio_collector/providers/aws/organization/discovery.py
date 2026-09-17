from __future__ import annotations

# ruff: noqa: ANN401, D100, D102, EM101, EM102, PERF401, TC001, TC003, TRY003
import re
from collections.abc import Iterable
from typing import Any, Literal

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.session import get_account_context
from unio_collector.config.organization import AwsOrganizationConfig
from unio_collector.providers.aws.organization.discovery_result import OrganizationDiscoveryResult
from unio_collector.providers.aws.organization.selection import (
    OrganizationAccountSelector,
)
from unio_collector.scan_workflow.organization.model.account import AccountIdentity, AwsAccountState
from unio_collector.scan_workflow.organization.model.authority import OrganizationCallerAuthority
from unio_collector.scan_workflow.organization.model.organization import OrganizationIdentity
from unio_collector.scan_workflow.organization.model.unit import OrganizationalUnit

TagEvidenceStatus = Literal["not_requested", "available", "unavailable"]

_ALIAS_PART = re.compile(r"[^a-z0-9-]+")
_DISCOVERY_CALLS = (
    "organizations:DescribeOrganization",
    "organizations:ListRoots",
    "organizations:ListOrganizationalUnitsForParent",
    "organizations:ListAccountsForParent",
    "organizations:ListTagsForResource",
    "organizations:ListDelegatedServicesForAccount",
)


class AwsOrganizationDiscovery:
    """Discover an AWS Organization using audited, read-only APIs."""

    def discover(self, session: Any, config: AwsOrganizationConfig) -> OrganizationDiscoveryResult:
        caller = get_account_context(session)
        caller_account = str(caller["account_id"])
        if caller_account != config.authorization.expected_caller_account_id:
            raise ValueError("STS caller account does not match expected_caller_account_id.")
        context = AwsAuditContext(
            scanner_id="unio-collector-organization-discovery",
            collector="AwsOrganizationDiscovery",
            allowed_api_calls=_DISCOVERY_CALLS,
            recipient_account_id=caller_account,
        )
        client = session.create_client("organizations", region_name="us-east-1", audit_context=context)
        description = client.describe_organization().get("Organization")
        if not isinstance(description, dict):
            raise ValueError("DescribeOrganization did not return an Organization object.")
        management_id = self._required_text(description, "MasterAccountId")
        organization_id = self._required_text(description, "Id")
        organization_arn = self._required_text(description, "Arn")
        feature_set = self._required_text(description, "FeatureSet")
        roots = tuple(self._pages(client.list_roots, "Roots"))
        if not roots:
            raise ValueError("AWS Organizations discovery returned no root.")

        units: list[OrganizationalUnit] = []
        raw_accounts: list[tuple[dict[str, Any], str, tuple[str, ...]]] = []
        visited: set[str] = set()
        for root in sorted(roots, key=lambda item: str(item.get("Id", ""))):
            root_id = self._required_text(root, "Id")
            self._walk_parent(client, root_id, root_id, (), visited, units, raw_accounts)

        account_metadata = config.account_metadata
        aliases: set[str] = set()
        discovered_account_ids: set[str] = set()
        accounts: list[AccountIdentity] = []
        wants_tags = bool(config.selection.account_tag_selectors)
        for index, (raw, parent_id, path) in enumerate(sorted(raw_accounts, key=lambda item: str(item[0].get("Id", ""))), 1):
            account_id = self._required_text(raw, "Id")
            if account_id in discovered_account_ids:
                raise ValueError(
                    f"AWS Organizations returned duplicate account ID {account_id}.",
                )
            discovered_account_ids.add(account_id)
            metadata_entry = account_metadata.get(account_id, {})
            alias = self._alias(metadata_entry.get("alias"), index, aliases)
            aliases.add(alias)
            tags, tag_status, tag_limitations = self._tags(client, account_id) if wants_tags else ({}, "not_requested", ())
            labels_raw = metadata_entry.get("labels", {})
            labels = {str(key): self._metadata_values(value) for key, value in labels_raw.items()} if isinstance(labels_raw, dict) else {}
            accounts.append(
                AccountIdentity(
                    account_id=account_id,
                    arn=self._required_text(raw, "Arn"),
                    name=str(raw["Name"]) if raw.get("Name") else None,
                    alias=alias,
                    state=self._state(raw.get("State")),
                    parent_id=parent_id,
                    organizational_unit_path=path,
                    joined_method=str(raw["JoinedMethod"]) if raw.get("JoinedMethod") else None,
                    joined_timestamp=(raw["JoinedTimestamp"].isoformat() if hasattr(raw.get("JoinedTimestamp"), "isoformat") else None),
                    tags=tags,
                    tag_evidence_status=tag_status,
                    metadata=labels,
                    metadata_provenance="operator" if labels else "none",
                    is_management_account=account_id == management_id,
                    limitations=tag_limitations,
                ),
            )

        authority = self._authority(client, config, caller_account, management_id)
        organization = OrganizationIdentity(
            organization_id=organization_id,
            organization_arn=organization_arn,
            feature_set=feature_set,
            management_account_id=management_id,
            caller_account_id=caller_account,
            authority=authority,
            alias=self._organization_alias(organization_id),
        )
        normalized_units = tuple(sorted(units, key=lambda item: (item.ancestor_path, item.organizational_unit_id)))
        normalized_accounts = tuple(sorted(accounts, key=lambda item: item.account_id))
        selected = OrganizationAccountSelector().select(
            accounts=normalized_accounts,
            organizational_units=normalized_units,
            selection=config.selection,
        )
        return OrganizationDiscoveryResult(organization, normalized_units, normalized_accounts, selected)

    def _walk_parent(
        self,
        client: Any,
        parent_id: str,
        root_id: str,
        path: tuple[str, ...],
        visited: set[str],
        units: list[OrganizationalUnit],
        accounts: list[tuple[dict[str, Any], str, tuple[str, ...]]],
    ) -> None:
        if parent_id in visited:
            raise ValueError(f"Cycle detected in AWS Organizations hierarchy at {parent_id}.")
        visited.add(parent_id)
        for account in self._pages(client.list_accounts_for_parent, "Accounts", ParentId=parent_id):
            accounts.append((account, parent_id, path))
        children = sorted(
            self._pages(client.list_organizational_units_for_parent, "OrganizationalUnits", ParentId=parent_id),
            key=lambda item: str(item.get("Id", "")),
        )
        for child in children:
            child_id = self._required_text(child, "Id")
            child_path = (*path, child_id)
            units.append(
                OrganizationalUnit(
                    organizational_unit_id=child_id,
                    arn=self._required_text(child, "Arn"),
                    name=str(child.get("Name", "")),
                    parent_id=parent_id,
                    root_id=root_id,
                    ancestor_path=child_path,
                ),
            )
            self._walk_parent(client, child_id, root_id, child_path, visited, units, accounts)

    def _required_text(self, payload: dict[str, Any], key: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"AWS Organizations did not return a complete {key} identity field.")
        return value

    def _pages(self, operation: Any, result_key: str, **kwargs: Any) -> Iterable[dict[str, Any]]:
        token: str | None = None
        seen_tokens: set[str] = set()
        while True:
            request = dict(kwargs)
            if token is not None:
                request["NextToken"] = token
            response = operation(**request)
            if not isinstance(response, dict):
                raise ValueError(f"AWS Organizations {result_key} response must be an object.")
            values = response.get(result_key)
            if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
                raise ValueError(f"AWS Organizations {result_key} response must contain a complete list of objects.")
            token_value = response.get("NextToken")
            if token_value not in (None, ""):
                if not isinstance(token_value, str) or not token_value.strip():
                    raise ValueError("AWS Organizations returned an invalid pagination token.")
                if token_value in seen_tokens:
                    raise ValueError("AWS Organizations returned a repeated pagination token.")
                seen_tokens.add(token_value)
            yield from values
            if token_value in (None, ""):
                return
            token = token_value

    def _tags(
        self,
        client: Any,
        account_id: str,
    ) -> tuple[dict[str, str], TagEvidenceStatus, tuple[str, ...]]:
        try:
            items = list(self._pages(client.list_tags_for_resource, "Tags", ResourceId=account_id))
        except Exception as exc:
            if not aws_errors.is_permission_error(exc):
                raise
            return (
                {},
                "unavailable",
                ("Account-tag evidence was permission denied; tag selectors fail closed.",),
            )
        tags: dict[str, str] = {}
        for item in items:
            key, value = item.get("Key"), item.get("Value")
            if not isinstance(key, str) or not key or not isinstance(value, str):
                raise ValueError("AWS Organizations returned incomplete account-tag evidence.")
            if key in tags:
                raise ValueError("AWS Organizations returned duplicate account-tag evidence.")
            tags[key] = value
        return tags, "available", ()

    def _authority(
        self,
        client: Any,
        config: AwsOrganizationConfig,
        caller: str,
        management: str,
    ) -> OrganizationCallerAuthority:
        declared = config.authorization.caller_context
        if declared == "management":
            if caller != management:
                raise ValueError("Declared management caller is not the AWS-confirmed management account.")
            return OrganizationCallerAuthority(
                declared_context=declared,
                observed_authority="aws_confirmed_management",
                evidence_status="confirmed",
                evidence_apis=("sts:GetCallerIdentity", "organizations:DescribeOrganization"),
            )
        if declared == "delegated_administrator":
            services = tuple(
                sorted(
                    {
                        self._required_text(item, "ServicePrincipal")
                        for item in self._pages(client.list_delegated_services_for_account, "DelegatedServices", AccountId=caller)
                    }
                )
            )
            if not services:
                raise ValueError("AWS did not confirm the caller as a service delegated administrator.")
            return OrganizationCallerAuthority(
                declared_context=declared,
                observed_authority="aws_confirmed_service_delegated_administrator",
                evidence_status="confirmed",
                delegated_service_principals=services,
                evidence_apis=("organizations:ListDelegatedServicesForAccount",),
            )
        return OrganizationCallerAuthority(
            declared_context="operator",
            observed_authority="operator_with_observed_organizations_read_access",
            evidence_status="observed_access",
            evidence_apis=("organizations:DescribeOrganization", "organizations:ListRoots"),
            limitations=("Organizations read access does not prove delegated-administrator designation.",),
        )

    def _alias(self, configured: object, index: int, used: set[str]) -> str:
        candidate = _ALIAS_PART.sub("-", str(configured or "").strip().lower()).strip("-")
        candidate = candidate or f"account-{index:03d}"
        if candidate in used:
            raise ValueError(f"Duplicate organization account alias: {candidate}")
        return candidate

    def _organization_alias(self, organization_id: str) -> str:
        suffix = organization_id.rsplit("-", maxsplit=1)[-1][-8:]
        return f"organization-{suffix or 'unknown'}"

    def _metadata_values(self, value: object) -> tuple[str, ...]:
        if isinstance(value, list):
            return tuple(sorted(str(item) for item in value))
        return (str(value),)

    def _state(self, value: object) -> AwsAccountState:
        state = str(value or "UNKNOWN")
        allowed = {"PENDING_ACTIVATION", "ACTIVE", "SUSPENDED", "PENDING_CLOSURE", "CLOSED"}
        return state if state in allowed else "UNKNOWN"  # type: ignore[return-value]
