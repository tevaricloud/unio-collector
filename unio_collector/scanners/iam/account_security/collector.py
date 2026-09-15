from __future__ import annotations  # noqa: D100

from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.response_admission import (
    ProviderResponseError,
    iter_response_rows,
    require_complete_response,
    require_response_mapping,
    require_response_rows,
    require_response_string,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.iam.access_key_record import IamAccessKeyRecord
from unio_collector.scanners.iam.account_security.evidence import IamAccountSecurityEvidence
from unio_collector.scanners.iam.account_security.options import (
    IamAccountSecurityCollectionOptions,
)
from unio_collector.scanners.iam.security_helpers import (
    IAM_POLICY_DETAIL_MODES,
    IamSecurityHelperMixin,
    normalize_datetime,
    require_iam_password_policy,
)
from unio_collector.scanners.iam.user_security_record import IamUserSecurityRecord
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from datetime import datetime

    from unio_collector.scanners.iam.policy_grant_record import IamPolicyGrantRecord
    from unio_collector.scanners.scanner.context import ScannerContext


class IamAccountSecurityCollector(IamSecurityHelperMixin, BaseUnioScanner):
    """Collect IAM account security evidence without finding evaluation."""

    def collect(self, context: ScannerContext) -> IamAccountSecurityEvidence:  # noqa: D102
        options = self._get_collection_options(context)
        client = context.security.create_client(
            "iam",
            collector_name="IamAccountSecurityReviewScanner",
        )
        warnings: list[str] = []
        account_summary = self._call_mapping(
            client.get_account_summary,
            "SummaryMap",
            warnings,
            "IAM account summary",
        )
        password_status: dict[str, str] = {}
        password_policy = self._get_password_policy(client, warnings, password_status)
        root_mfa = account_summary.get("AccountMFAEnabled")
        if type(root_mfa) is not int or root_mfa not in (0, 1):
            self._record_warning(warnings, "IAM root MFA observation", ProviderResponseError())
        users = tuple(self._collect_users(context, client, warnings))
        policy_grants = tuple(
            self._collect_policy_grants(client, users, warnings, options),
        )
        self._record_policy_detail_coverage(context, options)
        self._record_password_policy_coverage(context, password_policy)
        for warning in warnings:
            context.warnings.add(warning)
        return IamAccountSecurityEvidence(
            account_summary=account_summary,
            password_policy=password_policy,
            users=users,
            policy_grants=policy_grants,
            warnings=tuple(warnings),
            account_id=context.security.account_id,
            collection_evidence_version=1,
            password_policy_status=password_status["status"],
        )

    def describe_implementation(self) -> ScannerImplementation:  # noqa: D102
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="IamAccountSecurityReviewScanner",
            implementation_module=("unio_collector.scanners.iam.account_security.scanner"),
        )

    def _get_collection_options(
        self,
        context: ScannerContext,
    ) -> IamAccountSecurityCollectionOptions:
        raw_mode = context.options.get(
            "policy_detail_mode",
            "administrator-access-only",
        )
        mode = str(raw_mode or "administrator-access-only").strip().lower()
        if mode not in IAM_POLICY_DETAIL_MODES:
            mode = "administrator-access-only"
        return IamAccountSecurityCollectionOptions(policy_detail_mode=mode)

    def _record_policy_detail_coverage(
        self,
        context: ScannerContext,
        options: IamAccountSecurityCollectionOptions,
    ) -> None:
        if options.policy_detail_mode == "full":
            summary = "IAM policy detail mode collected direct AdministratorAccess attachments and inline wildcard administrator policies."
            impact = "The scanner checks both managed AdministratorAccess attachment signals and inline Action=* Resource=* policy statements."
        elif options.policy_detail_mode == "off":
            summary = "IAM policy detail collection was disabled by configuration."
            impact = "The scanner did not check AdministratorAccess attachments or inline wildcard administrator policies."
        else:
            summary = "IAM policy detail mode collected direct AdministratorAccess attachments without expanding inline policies."
            impact = (
                "Inline IAM policies were not expanded by default; set "
                "scanners.iam-account-security-review.policy_detail_mode to "
                "full for inline Action=* Resource=* detection."
            )
        context.warnings.add_coverage_note(
            {
                "note_type": "execution_detail",
                "summary": summary,
                "config_key": ("scanners.iam-account-security-review.policy_detail_mode"),
                "configured_value": options.policy_detail_mode,
                "impact": impact,
                "result_scope": "current_scan",
            },
        )

    def _record_password_policy_coverage(
        self,
        context: ScannerContext,
        password_policy: dict[str, Any] | None,
    ) -> None:
        if password_policy is None:
            context.warnings.add_coverage_note(
                {
                    "note_type": "execution_detail",
                    "scope_area": "iam_password_policy",
                    "summary": ("IAM account password policy was not visible from iam:GetAccountPasswordPolicy."),
                    "status": "not_visible",
                    "result_scope": "current_scan",
                    "impact": (
                        "This applies only to IAM users. Validate IAM Identity "
                        "Center or external identity-provider password controls "
                        "separately where they are authoritative."
                    ),
                },
            )
            return
        context.warnings.add_coverage_note(
            {
                "note_type": "execution_detail",
                "scope_area": "iam_password_policy",
                "summary": ("IAM account password policy was visible from iam:GetAccountPasswordPolicy."),
                "status": "visible",
                "minimum_password_length": password_policy.get("MinimumPasswordLength"),
                "require_symbols": password_policy.get("RequireSymbols"),
                "require_numbers": password_policy.get("RequireNumbers"),
                "require_uppercase": password_policy.get("RequireUppercaseCharacters"),
                "require_lowercase": password_policy.get("RequireLowercaseCharacters"),
                "password_reuse_prevention": password_policy.get(
                    "PasswordReusePrevention",
                ),
                "max_password_age": password_policy.get("MaxPasswordAge"),
                "allow_users_to_change_password": password_policy.get(
                    "AllowUsersToChangePassword",
                ),
                "hard_expiry": password_policy.get("HardExpiry"),
                "result_scope": "current_scan",
                "impact": ("This evidence covers IAM user passwords only; IAM Identity Center and external identity providers need separate policy evidence."),
            },
        )

    def _get_password_policy(
        self,
        client: Any,  # noqa: ANN401
        warnings: list[str],
        status: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        if status is not None:
            status["status"] = "unavailable"
        try:
            response = client.get_account_password_policy()
            policy = require_response_mapping(require_response_mapping(response).get("PasswordPolicy"))
            require_iam_password_policy(policy)
        except Exception as exc:  # noqa: BLE001
            if aws_errors.get_aws_error_code(exc) == "NoSuchEntity":
                if status is not None:
                    status["status"] = "absent"
                return None
            self._record_warning(warnings, "IAM password policy", exc)
            return None
        if status is not None:
            status["status"] = "complete"
        return policy

    def _collect_users(
        self,
        context: ScannerContext,
        client: Any,  # noqa: ANN401
        warnings: list[str],
    ) -> list[IamUserSecurityRecord]:
        users: list[IamUserSecurityRecord] = []
        raw_users: list[dict[str, Any]] = []
        try:
            pages = client.get_paginator("list_users").paginate()
            for item in iter_response_rows(pages, "Users"):
                require_response_string(item.get("UserName"))
                raw_users.append(item)
        except Exception as exc:  # noqa: BLE001
            self._record_warning(warnings, "IAM users", exc)
        user_names = [str(raw_user.get("UserName", "")) for raw_user in raw_users if str(raw_user.get("UserName", "")).strip()]
        worker_count = (
            min(
                self._get_max_user_workers(context),
                len(user_names),
            )
            if user_names
            else 1
        )
        if worker_count > 1:
            raw_users_by_name = {str(raw_user.get("UserName", "")): raw_user for raw_user in raw_users if str(raw_user.get("UserName", "")).strip()}
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                return [
                    record
                    for record in executor.map(
                        lambda name: self._build_user_security_record(
                            client,
                            raw_users_by_name[name],
                            warnings,
                        ),
                        user_names,
                    )
                    if record is not None
                ]
        for raw_user in raw_users:
            record = self._build_user_security_record(client, raw_user, warnings)
            if record is not None:
                users.append(record)
        return users

    def _build_user_security_record(
        self,
        client: Any,  # noqa: ANN401
        raw_user: dict[str, Any],
        warnings: list[str],
    ) -> IamUserSecurityRecord | None:
        user_name = str(raw_user.get("UserName", ""))
        if not user_name:
            return None
        try:
            login_profile_created_at = self._get_login_profile_created_at(client, user_name)
            has_console_profile = login_profile_created_at is not None
        except Exception as exc:  # noqa: BLE001
            self._record_warning(warnings, f"IAM login profile for {user_name}", exc)
            login_profile_created_at = None
            has_console_profile = None
        return IamUserSecurityRecord(
            user_name=user_name,
            user_id=raw_user.get("UserId"),
            arn=raw_user.get("Arn"),
            has_console_profile=has_console_profile,
            login_profile_created_at=login_profile_created_at,
            password_last_used_at=normalize_datetime(raw_user.get("PasswordLastUsed")),
            mfa_device_count=self._count_mfa_devices(client, user_name, warnings),
            access_keys=tuple(self._list_access_keys(client, user_name, warnings)),
        )

    def _get_max_user_workers(self, context: ScannerContext) -> int:
        default_workers = self._get_default_user_workers(context)
        raw_value = context.options.get("max_user_workers", default_workers)
        try:
            return max(1, int(str(raw_value)))
        except (TypeError, ValueError):
            return default_workers

    def _get_default_user_workers(self, context: ScannerContext) -> int:
        runtime_config = getattr(context.security.session, "runtime_config", None)
        configured = getattr(runtime_config, "max_workers", 8)
        try:
            return max(1, min(16, int(configured)))
        except (TypeError, ValueError):
            return 8

    def _get_login_profile_created_at(
        self,
        client: Any,  # noqa: ANN401
        user_name: str,
    ) -> datetime | None:
        try:
            response = client.get_login_profile(UserName=user_name)
        except Exception as exc:
            if aws_errors.get_aws_error_code(exc) == "NoSuchEntity":
                return None
            raise
        login_profile = require_response_mapping(require_response_mapping(response).get("LoginProfile"))
        created_at = normalize_datetime(login_profile.get("CreateDate"))
        if created_at is None:
            raise ProviderResponseError
        return created_at

    def _count_mfa_devices(
        self,
        client: Any,  # noqa: ANN401
        user_name: str,
        warnings: list[str],
    ) -> int | None:
        try:
            response = client.list_mfa_devices(UserName=user_name)
            devices = require_response_rows(response, "MFADevices")
            require_complete_response(response)
        except Exception as exc:  # noqa: BLE001
            self._record_warning(warnings, f"IAM MFA devices for {user_name}", exc)
            return None
        return len(devices)

    def _list_access_keys(
        self,
        client: Any,  # noqa: ANN401
        user_name: str,
        warnings: list[str],
    ) -> list[IamAccessKeyRecord]:
        metadata: list[dict[str, Any]] = []
        try:
            response = client.list_access_keys(UserName=user_name)
            metadata.extend(require_response_rows(response, "AccessKeyMetadata"))
            require_complete_response(response)
        except Exception as exc:  # noqa: BLE001
            self._record_warning(warnings, f"IAM access keys for {user_name}", exc)
        records: list[IamAccessKeyRecord] = []
        for item in metadata:
            try:
                key_id = require_response_string(item.get("AccessKeyId"))
                status = require_response_string(item.get("Status"))
            except ProviderResponseError as exc:
                self._record_warning(warnings, f"IAM access keys for {user_name}", exc)
                continue
            records.append(
                IamAccessKeyRecord(
                    access_key_id=key_id,
                    status=status,
                    created_at=normalize_datetime(item.get("CreateDate")),
                    **self._get_access_key_last_used(
                        client,
                        key_id,
                        warnings,
                    ),
                )
            )
        return records

    def _get_access_key_last_used(
        self,
        client: Any,  # noqa: ANN401
        access_key_id: str,
        warnings: list[str] | None = None,
    ) -> dict[str, Any]:
        if not access_key_id:
            return {"last_used_available": False}
        try:
            response = client.get_access_key_last_used(AccessKeyId=access_key_id)
            last_used = require_response_mapping(require_response_mapping(response).get("AccessKeyLastUsed"))
            require_response_string(last_used.get("ServiceName"))
            require_response_string(last_used.get("Region"))
            if last_used.get("LastUsedDate") is not None:
                self._require_last_used_datetime(last_used["LastUsedDate"])
        except Exception as exc:  # noqa: BLE001
            if warnings is not None:
                self._record_warning(warnings, f"IAM access key last use for {access_key_id}", exc)
            return {"last_used_available": False}
        return {
            "last_used_at": normalize_datetime(last_used.get("LastUsedDate")),
            "last_used_service": (str(last_used.get("ServiceName")) if last_used.get("ServiceName") else None),
            "last_used_region": (str(last_used.get("Region")) if last_used.get("Region") else None),
        }

    def _require_last_used_datetime(self, value: object) -> None:
        if normalize_datetime(value) is None:
            raise ProviderResponseError

    def _collect_policy_grants(
        self,
        client: Any,  # noqa: ANN401
        users: tuple[IamUserSecurityRecord, ...],
        warnings: list[str],
        options: IamAccountSecurityCollectionOptions,
    ) -> list[IamPolicyGrantRecord]:
        grants: list[IamPolicyGrantRecord] = []
        if options.policy_detail_mode == "off":
            return grants
        grants.extend(
            self._collect_administrator_access_policy_grants(client, warnings),
        )
        if options.policy_detail_mode != "full":
            return grants
        for user in users:
            grants.extend(
                self._collect_principal_policy_grants(
                    client,
                    principal_type="user",
                    principal_name=user.user_name,
                    principal_arn=user.arn,
                    inline_list_operation="list_user_policies",
                    inline_get_operation="get_user_policy",
                    inline_list_key="PolicyNames",
                    identity_argument={"UserName": user.user_name},
                    warnings=warnings,
                ),
            )
        for group in self._collect_groups(client, warnings):
            group_name = str(group.get("GroupName") or "")
            if not group_name:
                continue
            grants.extend(
                self._collect_principal_policy_grants(
                    client,
                    principal_type="group",
                    principal_name=group_name,
                    principal_arn=str(group.get("Arn")) if group.get("Arn") else None,
                    inline_list_operation="list_group_policies",
                    inline_get_operation="get_group_policy",
                    inline_list_key="PolicyNames",
                    identity_argument={"GroupName": group_name},
                    warnings=warnings,
                ),
            )
        for role in self._collect_roles(client, warnings):
            role_name = str(role.get("RoleName") or "")
            if not role_name:
                continue
            grants.extend(
                self._collect_principal_policy_grants(
                    client,
                    principal_type="role",
                    principal_name=role_name,
                    principal_arn=str(role.get("Arn")) if role.get("Arn") else None,
                    inline_list_operation="list_role_policies",
                    inline_get_operation="get_role_policy",
                    inline_list_key="PolicyNames",
                    identity_argument={"RoleName": role_name},
                    warnings=warnings,
                ),
            )
        return grants
