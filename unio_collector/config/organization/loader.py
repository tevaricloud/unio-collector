from __future__ import annotations

# ruff: noqa: D100, D102, EM101, EM102, TRY003
import math
import re
from pathlib import Path
from typing import Any

import yaml

from unio_collector.config.organization.config import AwsOrganizationConfig
from unio_collector.scan_workflow.organization.request.audit_role import AuditRoleConfiguration
from unio_collector.scan_workflow.organization.request.authorization import OrganizationAuthorization
from unio_collector.scan_workflow.organization.request.external_id import ExternalIdReference
from unio_collector.scan_workflow.organization.request.policy import OrganizationExecutionPolicy
from unio_collector.scan_workflow.organization.request.selection import TargetAccountSelection

_ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
_OU_ID = re.compile(r"^ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}$")


class AwsOrganizationConfigLoader:
    """Load the explicit, fail-closed AWS organization configuration."""

    def load(self, path: Path) -> AwsOrganizationConfig:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Config file root must be a mapping.")
        provider = self._mapping(raw, "scan").get("provider", "aws")
        if str(provider).strip().lower() != "aws":
            raise ValueError("AWS organization assessment requires scan.provider: aws.")
        aws = self._mapping(raw, "aws")
        organization = self._mapping(aws, "organization", required=True)
        authorization = self._authorization(
            self._mapping(organization, "authorization", required=True),
        )
        selection = self._selection(
            self._mapping(organization, "selection", required=True),
        )
        role = self._role(self._mapping(organization, "audit_role", required=True))
        execution = self._execution(self._mapping(organization, "execution"))
        metadata = self._account_metadata(
            self._mapping(organization, "account_metadata"),
        )
        if role.duration_seconds < execution.account_timeout_seconds + 60:
            raise ValueError(
                "aws.organization.audit_role.duration_seconds must exceed the account timeout by at least 60 seconds.",
            )
        return AwsOrganizationConfig(
            authorization=authorization,
            selection=selection,
            audit_role=role,
            execution=execution,
            account_metadata=metadata,
        )

    def _authorization(self, value: dict[str, Any]) -> OrganizationAuthorization:
        if value.get("cross_account_assessment") is not True:
            raise ValueError(
                "aws.organization.authorization.cross_account_assessment must be true.",
            )
        context = str(value.get("caller_context", "")).strip().lower()
        if context not in {"management", "delegated_administrator", "operator"}:
            raise ValueError("caller_context must be management, delegated_administrator, or operator.")
        expected = self._account_id(value.get("expected_caller_account_id"), "expected_caller_account_id")
        return OrganizationAuthorization(
            cross_account_assessment=True,
            caller_context=context,  # type: ignore[arg-type]
            expected_caller_account_id=expected,
            allow_chargeable_accounts=value.get("allow_chargeable_accounts") is True,
            allow_chargeable_retry=value.get("allow_chargeable_retry") is True,
        )

    def _selection(self, value: dict[str, Any]) -> TargetAccountSelection:
        tag_selectors = tuple(
            (
                self._nonempty(item.get("key"), "account_tags.key"),
                tuple(sorted(self._string_list(item.get("values"), "account_tags.values"))),
            )
            for item in self._mapping_list(value.get("account_tags"), "account_tags")
        )
        metadata = self._selector_mapping(value.get("metadata"), "metadata")
        result = TargetAccountSelection(
            account_ids=tuple(sorted(self._account_ids(value.get("account_ids")))),
            organizational_unit_ids=tuple(sorted(self._ou_ids(value.get("ou_ids")))),
            account_tag_selectors=tag_selectors,
            metadata_selectors=metadata,
            denied_account_ids=tuple(sorted(self._account_ids(value.get("deny_account_ids")))),
            denied_organizational_unit_ids=tuple(sorted(self._ou_ids(value.get("deny_ou_ids")))),
            include_descendants=value.get("include_descendants") is True,
            all_active_accounts=value.get("all_active_accounts") is True,
            include_management_account=value.get("include_management_account") is True,
        )
        if not result.has_positive_selector:
            raise ValueError("At least one positive organization account selector is required.")
        return result

    def _role(self, value: dict[str, Any]) -> AuditRoleConfiguration:
        role_name = self._optional_string(value.get("role_name"))
        arn_template = self._optional_string(value.get("arn_template"))
        if bool(role_name) == bool(arn_template):
            raise ValueError("Exactly one of audit_role.role_name or arn_template is required.")
        if arn_template and "{account_id}" not in arn_template:
            raise ValueError("audit_role.arn_template must contain {account_id}.")
        duration = self._bounded_int(value.get("duration_seconds", 3600), 900, 3600, "duration_seconds")
        external_raw = value.get("external_id")
        external = None
        if external_raw is not None:
            external_map = self._mapping_value(external_raw, "external_id")
            unknown = set(external_map) - {"environment_variable", "file"}
            if unknown:
                raise ValueError("External ID literals and unknown source keys are not allowed.")
            environment = self._optional_string(external_map.get("environment_variable"))
            file_value = self._optional_string(external_map.get("file"))
            if bool(environment) == bool(file_value):
                raise ValueError("external_id requires exactly one environment_variable or file source.")
            external = ExternalIdReference(
                environment_variable=environment,
                file=Path(file_value) if file_value else None,
            )
        return AuditRoleConfiguration(
            role_name=role_name,
            arn_template=arn_template,
            session_name_prefix=self._nonempty(value.get("session_name_prefix", "unio_collector"), "session_name_prefix"),
            duration_seconds=duration,
            external_id=external,
        )

    def _execution(self, value: dict[str, Any]) -> OrganizationExecutionPolicy:
        backoff = float(value.get("retry_backoff_seconds", 2))
        if not math.isfinite(backoff) or backoff < 0:
            raise ValueError("retry_backoff_seconds must be finite and non-negative.")
        return OrganizationExecutionPolicy(
            max_concurrency=self._bounded_int(value.get("max_concurrency", 2), 1, 16, "max_concurrency"),
            account_timeout_seconds=self._bounded_int(value.get("account_timeout_seconds", 3300), 120, 3540, "account_timeout_seconds"),
            max_attempts=self._bounded_int(value.get("max_attempts", 2), 1, 5, "max_attempts"),
            retry_backoff_seconds=backoff,
            cancellation_grace_seconds=self._bounded_int(value.get("cancellation_grace_seconds", 30), 0, 300, "cancellation_grace_seconds"),
        )

    def _account_metadata(self, value: dict[str, Any]) -> dict[str, dict[str, object]]:
        result: dict[str, dict[str, object]] = {}
        for account_id, metadata in value.items():
            normalized = self._account_id(account_id, "account_metadata account ID")
            result[normalized] = dict(self._mapping_value(metadata, f"account_metadata.{account_id}"))
        return result

    def _selector_mapping(self, value: object, key: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
        if value is None:
            return ()
        mapping = self._mapping_value(value, key)
        return tuple((str(name), tuple(sorted(self._string_list(values, f"{key}.{name}")))) for name, values in sorted(mapping.items()))

    def _account_ids(self, value: object) -> list[str]:
        return [self._account_id(item, "account ID") for item in self._string_list(value, "account IDs")]

    def _ou_ids(self, value: object) -> list[str]:
        result = self._string_list(value, "OU IDs")
        for item in result:
            if not _OU_ID.fullmatch(item):
                raise ValueError(f"Invalid AWS Organizations OU ID: {item}")
        return result

    def _account_id(self, value: object, key: str) -> str:
        text = self._nonempty(value, key)
        if not _ACCOUNT_ID.fullmatch(text):
            raise ValueError(f"{key} must be a 12-digit AWS account ID.")
        return text

    def _mapping(self, value: dict[str, Any], key: str, *, required: bool = False) -> dict[str, Any]:
        child = value.get(key)
        if child is None and not required:
            return {}
        return self._mapping_value(child, key)

    def _mapping_value(self, value: object, key: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError(f"{key} must be a mapping.")
        return value

    def _mapping_list(self, value: object, key: str) -> list[dict[str, Any]]:
        if value is None:
            return []
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise ValueError(f"{key} must be a list of mappings.")
        return value

    def _string_list(self, value: object, key: str) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError(f"{key} must be a list.")
        return [self._nonempty(item, key) for item in value]

    def _nonempty(self, value: object, key: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError(f"{key} must not be empty.")
        return text

    def _optional_string(self, value: object) -> str | None:
        text = str(value or "").strip()
        return text or None

    def _bounded_int(self, value: object, minimum: int, maximum: int, key: str) -> int:
        parsed = int(str(value))
        if not minimum <= parsed <= maximum:
            raise ValueError(f"{key} must be between {minimum} and {maximum}.")
        return parsed
