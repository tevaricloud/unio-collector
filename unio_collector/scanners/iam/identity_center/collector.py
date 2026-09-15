from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws.response_admission import (
    ProviderResponseError,
    iter_response_rows,
    require_complete_response,
    require_response_mapping,
    require_response_rows,
    require_response_string,
    require_response_strings,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.iam.security_helpers import normalize_datetime
from unio_collector.scanners.identity_center.evidence import IdentityCenterEvidence
from unio_collector.scanners.identity_center.instance_record import (
    IdentityCenterInstanceRecord,
)
from unio_collector.scanners.identity_center.permission_set_record import (
    IdentityCenterPermissionSetRecord,
)
from unio_collector.scanners.security_governance.collection.warnings import append_warning

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


from unio_collector.scanners.scanner.implementation import ScannerImplementation


class IamIdentityCenterVisibilityReviewCollector(BaseUnioScanner):
    """Collect provider evidence for iam-identity-center-visibility-review."""

    def collect(self, context: ScannerContext) -> IdentityCenterEvidence:  # noqa: D102
        client = context.security.create_client(
            "sso-admin",
            collector_name="IamIdentityCenterVisibilityReviewScanner",
        )
        warnings: list[str] = []
        instances: list[IdentityCenterInstanceRecord] = []
        raw_instances: list[dict[str, Any]] = []
        try:
            response = client.list_instances()
            raw_instances.extend(require_response_rows(response, "Instances"))
            require_complete_response(response)
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, "IAM Identity Center instances", exc)
        for raw_instance in raw_instances:
            try:
                instance_arn = require_response_string(raw_instance.get("InstanceArn"))
                for field in ("IdentityStoreId", "OwnerAccountId", "Name", "Status"):
                    if raw_instance.get(field) is not None:
                        require_response_string(raw_instance[field])
            except ProviderResponseError as exc:
                append_warning(warnings, "IAM Identity Center instance detail", exc)
                continue
            identity_store_id = str(raw_instance.get("IdentityStoreId")) if raw_instance.get("IdentityStoreId") else None
            instances.append(
                IdentityCenterInstanceRecord(
                    instance_arn=instance_arn,
                    identity_store_id=identity_store_id,
                    owner_account_id=(str(raw_instance.get("OwnerAccountId")) if raw_instance.get("OwnerAccountId") else None),
                    name=str(raw_instance.get("Name")) if raw_instance.get("Name") else None,
                    status=str(raw_instance.get("Status")) if raw_instance.get("Status") else None,
                    created_at=normalize_datetime(raw_instance.get("CreatedDate")),
                    permission_sets=tuple(
                        self._collect_permission_sets(
                            client,
                            instance_arn=instance_arn,
                            identity_store_id=identity_store_id,
                            warnings=warnings,
                        ),
                    ),
                ),
            )
        for warning in warnings:
            context.warnings.add(warning)
        self._record_identity_center_coverage(context, instances, warnings)
        return IdentityCenterEvidence(
            instances=tuple(instances),
            warnings=tuple(warnings),
            account_id=context.security.account_id,
        )

    def _collect_permission_sets(
        self,
        client: Any,  # noqa: ANN401
        *,
        instance_arn: str,
        identity_store_id: str | None,
        warnings: list[str],
    ) -> list[IdentityCenterPermissionSetRecord]:
        permission_set_arns: list[str] = []
        try:
            pages = client.get_paginator("list_permission_sets").paginate(
                InstanceArn=instance_arn,
            )
            last_page: object = None
            for page in pages:
                permission_set_arns.extend(require_response_strings(page, "PermissionSets"))
                last_page = page
            require_complete_response(last_page)
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, "IAM Identity Center permission sets", exc)
        records: list[IdentityCenterPermissionSetRecord] = []
        for permission_set_arn in permission_set_arns:
            record = self._build_permission_set_record(
                client,
                instance_arn=instance_arn,
                identity_store_id=identity_store_id,
                permission_set_arn=permission_set_arn,
                warnings=warnings,
            )
            if record is not None:
                records.append(record)
        return records

    def _build_permission_set_record(
        self,
        client: Any,  # noqa: ANN401
        *,
        instance_arn: str,
        identity_store_id: str | None,
        permission_set_arn: str,
        warnings: list[str],
    ) -> IdentityCenterPermissionSetRecord | None:
        try:
            response = client.describe_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn,
            )
            raw_permission_set = require_response_mapping(require_response_mapping(response).get("PermissionSet"))
            require_response_string(raw_permission_set.get("Name"))
            for field in ("Description", "SessionDuration", "RelayState"):
                if raw_permission_set.get(field) is not None:
                    require_response_string(raw_permission_set[field])
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, "IAM Identity Center permission set detail", exc)
            return None
        return IdentityCenterPermissionSetRecord(
            instance_arn=instance_arn,
            identity_store_id=identity_store_id,
            permission_set_arn=permission_set_arn,
            name=str(raw_permission_set.get("Name") or permission_set_arn),
            description=str(raw_permission_set.get("Description")) if raw_permission_set.get("Description") else None,
            session_duration=str(raw_permission_set.get("SessionDuration")) if raw_permission_set.get("SessionDuration") else None,
            relay_state=str(raw_permission_set.get("RelayState")) if raw_permission_set.get("RelayState") else None,
            managed_policy_arns=tuple(
                self._list_permission_set_managed_policies(
                    client,
                    instance_arn=instance_arn,
                    permission_set_arn=permission_set_arn,
                    warnings=warnings,
                ),
            ),
            customer_managed_policy_names=tuple(
                self._list_permission_set_customer_policies(
                    client,
                    instance_arn=instance_arn,
                    permission_set_arn=permission_set_arn,
                    warnings=warnings,
                ),
            ),
        )

    def _list_permission_set_managed_policies(
        self,
        client: Any,  # noqa: ANN401
        *,
        instance_arn: str,
        permission_set_arn: str,
        warnings: list[str],
    ) -> list[str]:
        policy_arns: list[str] = []
        try:
            pages = client.get_paginator(
                "list_managed_policies_in_permission_set",
            ).paginate(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn,
            )
            policy_arns.extend(require_response_string(item.get("Arn")) for item in iter_response_rows(pages, "AttachedManagedPolicies"))
        except Exception as exc:  # noqa: BLE001
            append_warning(
                warnings,
                "IAM Identity Center managed policies in permission set",
                exc,
            )
        return policy_arns

    def _list_permission_set_customer_policies(
        self,
        client: Any,  # noqa: ANN401
        *,
        instance_arn: str,
        permission_set_arn: str,
        warnings: list[str],
    ) -> list[str]:
        operation = getattr(
            client,
            "list_customer_managed_policy_references_in_permission_set",
            None,
        )
        if not callable(operation):
            append_warning(warnings, "IAM Identity Center customer managed policies in permission set", ProviderResponseError())
            return []
        policy_names: list[str] = []
        try:
            response = operation(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn,
            )
            policy_names.extend(require_response_string(policy.get("Name")) for policy in require_response_rows(response, "CustomerManagedPolicyReferences"))
            require_complete_response(response)
        except Exception as exc:  # noqa: BLE001
            append_warning(
                warnings,
                "IAM Identity Center customer managed policies in permission set",
                exc,
            )
        return policy_names

    def _record_identity_center_coverage(
        self,
        context: ScannerContext,
        instances: list[IdentityCenterInstanceRecord],
        warnings: list[str],
    ) -> None:
        context.warnings.add_coverage_note(
            {
                "note_type": "execution_detail",
                "scope_area": "iam_identity_center",
                "status": "visible" if instances else "not_visible",
                "instance_count": len(instances),
                "permission_set_count": sum(len(instance.permission_sets) for instance in instances),
                "warning_count": len(warnings),
                "result_scope": "current_scan",
                "summary": (
                    "IAM Identity Center instance and permission set visibility was collected."
                    if instances
                    else "IAM Identity Center was not visible from sso-admin ListInstances."
                ),
                "impact": (
                    "This evidence covers AWS IAM Identity Center configuration "
                    "visibility only. It does not inspect external IdP password "
                    "policy, user lifecycle, or group membership intent."
                ),
            },
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="IamIdentityCenterVisibilityReviewScanner",
            implementation_module="unio_collector.scanners.iam.identity_center.scanner",
        )
