from __future__ import annotations

# ruff: noqa: D100, D102, EM101, TC001, TRY003
import os
import re
from importlib import import_module

from unio_collector.aws.api.call_ledger import ApiCallLedger
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.audited.session import AuditedAwsSession
from unio_collector.aws.session import get_account_context
from unio_collector.providers.aws.organization.execution_context import OrganizationAccountExecutionContext
from unio_collector.providers.aws.organization.role_audit import RoleAssumptionAuditRecord
from unio_collector.scan_workflow.organization.model.account import AccountIdentity
from unio_collector.scan_workflow.organization.request.audit_role import AuditRoleConfiguration

_SESSION_INVALID = re.compile(r"[^A-Za-z0-9+=,.@_-]+")


class AwsOrganizationRoleAssumer:
    """Assume and verify one explicitly selected account audit role."""

    def assume(
        self,
        *,
        management_session: AuditedAwsSession,
        account: AccountIdentity,
        role: AuditRoleConfiguration,
        partition: str,
        run_id: str,
    ) -> OrganizationAccountExecutionContext:
        role_arn = self.render_role_arn(role, account.account_id, partition)
        external_id, source_kind = self._resolve_external_id(role)
        context = AwsAuditContext(
            scanner_id="unio-collector-organization-role-assumption",
            collector="AwsOrganizationRoleAssumer",
            allowed_api_calls=("sts:AssumeRole",),
            recipient_account_id=account.account_id,
        )
        sts = management_session.create_client(
            "sts",
            region_name=management_session.get_region_name() or "us-east-1",
            audit_context=context,
        )
        request: dict[str, object] = {
            "RoleArn": role_arn,
            "RoleSessionName": self._session_name(role.session_name_prefix, run_id, account.alias),
            "DurationSeconds": role.duration_seconds,
        }
        if external_id is not None:
            request["ExternalId"] = external_id
        response = sts.assume_role(**request)
        credentials = response.get("Credentials", {})
        required = ("AccessKeyId", "SecretAccessKey", "SessionToken")
        if not isinstance(credentials, dict) or any(not credentials.get(key) for key in required):
            raise ValueError("STS AssumeRole did not return complete temporary credentials.")
        boto3 = import_module("boto3")
        boto_session = boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=management_session.get_region_name(),
        )
        ledger = ApiCallLedger()
        session = AuditedAwsSession(
            boto_session,
            ledger,
            runtime_config=management_session.runtime_config,
        )
        identity = get_account_context(session)
        if str(identity.get("account_id")) != account.account_id:
            raise ValueError("Assumed role identity does not match the selected target account.")
        metadata = response.get("ResponseMetadata", {})
        return OrganizationAccountExecutionContext(
            account=account,
            session=session,
            ledger=ledger,
            role_audit=RoleAssumptionAuditRecord(
                account_reference=account.alias,
                role_arn=role_arn,
                duration_seconds=role.duration_seconds,
                external_id_present=external_id is not None,
                external_id_source_kind=source_kind,
                request_id=(str(metadata.get("RequestId")) if isinstance(metadata, dict) and metadata.get("RequestId") else None),
                outcome="succeeded",
            ),
        )

    def render_role_arn(self, role: AuditRoleConfiguration, account_id: str, partition: str) -> str:
        if role.arn_template:
            rendered = role.arn_template.format(partition=partition, account_id=account_id)
        else:
            rendered = f"arn:{partition}:iam::{account_id}:role/{role.role_name}"
        prefix = f"arn:{partition}:iam::{account_id}:role/"
        if not rendered.startswith(prefix):
            raise ValueError("Rendered audit role ARN does not belong to the selected account and partition.")
        return rendered

    def _resolve_external_id(self, role: AuditRoleConfiguration) -> tuple[str | None, str | None]:
        reference = role.external_id
        if reference is None:
            return None, None
        if reference.environment_variable:
            value = os.environ.get(reference.environment_variable)
            if value is None or not value.strip():
                raise ValueError("Configured external-ID environment variable is unset or empty.")
            return value.strip(), "environment_variable"
        if reference.file:
            value = reference.file.read_text(encoding="utf-8").strip()
            if not value:
                raise ValueError("Configured external-ID file is empty.")
            return value, "file"
        raise ValueError("External-ID reference has no supported source.")

    def _session_name(self, prefix: str, run_id: str, alias: str) -> str:
        value = _SESSION_INVALID.sub("-", f"{prefix}-{run_id}-{alias}").strip("-")
        return value[:64]
