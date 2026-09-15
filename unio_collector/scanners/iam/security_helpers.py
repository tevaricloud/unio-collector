# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.response_admission import (
    ProviderResponseError,
    iter_response_rows,
    require_complete_response,
    require_response_bool,
    require_response_mapping,
    require_response_rows,
    require_response_string,
    require_response_strings,
)
from unio_collector.scanners.iam.policy_grant_record import IamPolicyGrantRecord

IAM_ADMINISTRATOR_ACCESS_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
IAM_POLICY_DETAIL_MODES = frozenset({"administrator-access-only", "full", "off"})


def normalize_datetime(value: object) -> datetime | None:  # noqa: D103
    if isinstance(value, datetime):
        return ensure_aware_datetime(value)
    return None


def ensure_aware_datetime(value: datetime) -> datetime:  # noqa: D103
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def normalize_iam_policy_document(value: object) -> dict[str, Any] | None:  # noqa: D103
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value:
        return None
    try:
        decoded = unquote(value)
        document = json.loads(decoded)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def require_iam_policy_document(value: object) -> dict[str, Any]:
    """Require structurally observed inline statements without interpreting access."""
    document = require_response_mapping(normalize_iam_policy_document(value))
    raw_statements = document.get("Statement")
    statements = require_response_rows({"Statement": [raw_statements] if isinstance(raw_statements, dict) else raw_statements}, "Statement")
    if not statements:
        raise ProviderResponseError
    for statement in statements:
        if statement.get("Effect") not in {"Allow", "Deny"}:
            raise ProviderResponseError
        for positive, negative in (("Action", "NotAction"), ("Resource", "NotResource")):
            if (positive in statement) == (negative in statement):
                raise ProviderResponseError
            values = statement.get(positive, statement.get(negative))
            if isinstance(values, str):
                require_response_string(values)
            elif not require_response_strings({"Values": values}, "Values"):
                raise ProviderResponseError
    return document


def require_iam_password_policy(value: object) -> dict[str, Any]:
    """Admit observed IAM password controls without assigning private thresholds."""
    policy = require_response_mapping(value)
    for field in ("RequireSymbols", "RequireNumbers", "RequireUppercaseCharacters", "RequireLowercaseCharacters"):
        require_response_bool(policy.get(field))
    minimum = policy.get("MinimumPasswordLength")
    if type(minimum) is not int or minimum < 0:
        raise ProviderResponseError
    for field in ("PasswordReusePrevention", "MaxPasswordAge"):
        if field in policy and (type(policy[field]) is not int or policy[field] < 0):
            raise ProviderResponseError
    return policy


class IamSecurityHelperMixin:  # noqa: D101
    def _collect_administrator_access_policy_grants(
        self,
        client: Any,  # noqa: ANN401
        warnings: list[str],
    ) -> list[IamPolicyGrantRecord]:
        try:
            pages = client.get_paginator("list_entities_for_policy").paginate(
                PolicyArn=IAM_ADMINISTRATOR_ACCESS_POLICY_ARN,
            )
        except Exception as exc:  # noqa: BLE001
            self._record_warning(
                warnings,
                "IAM AdministratorAccess policy entities",
                exc,
            )
            return []
        grants: list[IamPolicyGrantRecord] = []
        last_page: object = None
        try:
            for page in pages:
                for key, principal_type, name_key in (
                    ("PolicyUsers", "user", "UserName"),
                    ("PolicyGroups", "group", "GroupName"),
                    ("PolicyRoles", "role", "RoleName"),
                ):
                    grants.extend(self._build_policy_entity_grants(require_response_rows(page, key), principal_type=principal_type, name_key=name_key))
                last_page = page
            require_complete_response(last_page)
        except Exception as exc:  # noqa: BLE001
            self._record_warning(warnings, "IAM AdministratorAccess policy entities", exc)
        return grants

    def _build_policy_entity_grants(
        self,
        entities: Any,  # noqa: ANN401
        *,
        principal_type: str,
        name_key: str,
    ) -> list[IamPolicyGrantRecord]:
        grants: list[IamPolicyGrantRecord] = []
        for entity in require_response_rows({"Entities": entities}, "Entities"):
            principal_name = require_response_string(entity.get(name_key))
            grants.append(
                IamPolicyGrantRecord(
                    principal_type=principal_type,
                    principal_name=principal_name,
                    principal_arn=None,
                    policy_source="managed",
                    policy_name="AdministratorAccess",
                    policy_arn=IAM_ADMINISTRATOR_ACCESS_POLICY_ARN,
                ),
            )
        return grants

    def _collect_groups(
        self,
        client: Any,  # noqa: ANN401
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        try:
            pages = client.get_paginator("list_groups").paginate()
            for item in iter_response_rows(pages, "Groups"):
                require_response_string(item.get("GroupName"))
                records.append(item)
        except Exception as exc:  # noqa: BLE001
            self._record_warning(warnings, "IAM groups", exc)
        return records

    def _collect_roles(
        self,
        client: Any,  # noqa: ANN401
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        try:
            pages = client.get_paginator("list_roles").paginate()
            for item in iter_response_rows(pages, "Roles"):
                require_response_string(item.get("RoleName"))
                records.append(item)
        except Exception as exc:  # noqa: BLE001
            self._record_warning(warnings, "IAM roles", exc)
        return records

    def _collect_principal_policy_grants(
        self,
        client: Any,  # noqa: ANN401
        *,
        principal_type: str,
        principal_name: str,
        principal_arn: str | None,
        inline_list_operation: str,
        inline_get_operation: str,
        inline_list_key: str,
        identity_argument: dict[str, str],
        warnings: list[str],
    ) -> list[IamPolicyGrantRecord]:
        return self._collect_inline_policy_grants(
            client,
            principal_type=principal_type,
            principal_name=principal_name,
            principal_arn=principal_arn,
            list_operation_name=inline_list_operation,
            get_operation_name=inline_get_operation,
            list_key=inline_list_key,
            identity_argument=identity_argument,
            warnings=warnings,
        )

    def _collect_inline_policy_grants(
        self,
        client: Any,  # noqa: ANN401
        *,
        principal_type: str,
        principal_name: str,
        principal_arn: str | None,
        list_operation_name: str,
        get_operation_name: str,
        list_key: str,
        identity_argument: dict[str, str],
        warnings: list[str],
    ) -> list[IamPolicyGrantRecord]:
        policy_names: list[str] = []
        try:
            pages = client.get_paginator(list_operation_name).paginate(
                **identity_argument,
            )
            last_page: object = None
            for page in pages:
                policy_names.extend(require_response_strings(page, list_key))
                last_page = page
            require_complete_response(last_page)
        except Exception as exc:  # noqa: BLE001
            self._record_warning(
                warnings,
                f"IAM inline policy list for {principal_type} {principal_name}",
                exc,
            )
        grants: list[IamPolicyGrantRecord] = []
        for policy_name in policy_names:
            try:
                response = getattr(client, get_operation_name)(
                    **identity_argument,
                    PolicyName=policy_name,
                )
                document = require_iam_policy_document(require_response_mapping(response).get("PolicyDocument"))
            except Exception as exc:  # noqa: BLE001
                self._record_warning(
                    warnings,
                    (f"IAM inline policy {policy_name} for {principal_type} {principal_name}"),
                    exc,
                )
                continue
            grants.append(
                IamPolicyGrantRecord(
                    principal_type=principal_type,
                    principal_name=principal_name,
                    principal_arn=principal_arn,
                    policy_source="inline",
                    policy_name=policy_name,
                    policy_document=document,
                ),
            )
        return grants

    def _call_mapping(
        self,
        operation: Any,  # noqa: ANN401
        response_key: str,
        warnings: list[str],
        label: str,
    ) -> dict[str, Any]:
        try:
            response = operation()
            value = require_response_mapping(require_response_mapping(response).get(response_key))
        except Exception as exc:  # noqa: BLE001
            self._record_warning(warnings, label, exc)
            return {}
        return value

    def _record_warning(
        self,
        warnings: list[str],
        label: str,
        error: Exception,
    ) -> None:
        code = aws_errors.get_aws_error_code(error) or error.__class__.__name__
        warnings.append(f"{label} evidence was unavailable ({code}).")
