# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, TypeVar

from unio_collector.aws.audit_cost.kms.key_evidence import KmsKeyEvidence
from unio_collector.aws.audit_cost.kms.record import KmsCostGovernanceRecord
from unio_collector.aws.audit_cost.secrets_manager.record import (
    SecretsManagerCostGovernanceRecord,
)
from unio_collector.aws.audit_cost.secrets_manager.secret_evidence import SecretEvidence

AuditRecordT = TypeVar("AuditRecordT")


class KeySecretAuditCollectionMixin:  # noqa: D101
    def _collect_kms_record(self, region: str) -> list[KmsCostGovernanceRecord]:
        client = self.session.create_client(
            "kms",
            region_name=region,
            audit_context=self.audit_context,
        )
        permission_errors: list[str] = []
        keys = self._collect_kms_key_refs(client, permission_errors)
        aliases = self._collect_kms_aliases(client, permission_errors)
        aws_managed_alias_key_ids = self._get_kms_aws_managed_alias_key_ids(
            aliases,
        )
        customer_alias_key_ids = self._get_kms_customer_alias_key_ids(aliases)
        alias_classified_aws_managed_key_ids = aws_managed_alias_key_ids - customer_alias_key_ids
        key_details: list[dict[str, Any]] = []
        inaccessible_key_ids: list[str] = []
        skipped_aws_managed_alias_key_ids: list[str] = []
        for key in keys:
            key_id = str(key.get("KeyId") or key.get("KeyArn") or "")
            if key_id in alias_classified_aws_managed_key_ids:
                skipped_aws_managed_alias_key_ids.append(key_id)
                continue
            error_count_before = len(permission_errors)
            metadata = self._collect_kms_key_metadata(
                client,
                key,
                permission_errors,
            )
            if metadata is not None:
                key_details.append(metadata)
                continue
            if self._last_error_is_permission_denied(
                permission_errors,
                error_count_before,
                method_name="describe_key",
            ):
                inaccessible_key_ids.append(key_id)
        customer_keys = [key for key in key_details if str(key.get("KeyManager") or "").upper() == "CUSTOMER"]
        rotation_status_by_key_id = {
            str(key.get("KeyId")): self._collect_kms_rotation_enabled(
                client,
                str(key.get("KeyId")),
                permission_errors,
            )
            for key in customer_keys
            if key.get("KeyId") and self._is_kms_rotation_status_applicable(key)
        }
        described_aws_managed_key_count = sum(1 for key in key_details if str(key.get("KeyManager") or "").upper() == "AWS")
        raw_keys: list[KmsKeyEvidence] = []
        for key in customer_keys:
            key_id = str(key.get("KeyId") or "")
            tag_count: int | None = None
            tag_read_state = "unknown"
            if key_id:
                error_count_before = len(permission_errors)
                tags = self._collect_kms_key_tags(
                    client,
                    key_id,
                    permission_errors,
                )
                if len(permission_errors) == error_count_before:
                    tag_count = len(tags)
                    tag_read_state = "known_tagged" if tags else "known_untagged"
            raw_keys.append(
                KmsKeyEvidence(
                    key_id=key_id,
                    key_manager=str(key.get("KeyManager") or ""),
                    key_state=str(key.get("KeyState") or ""),
                    key_spec=str(key.get("KeySpec") or ""),
                    key_usage=str(key.get("KeyUsage") or ""),
                    origin=str(key.get("Origin") or ""),
                    multi_region=bool(key.get("MultiRegion")),
                    multi_region_key_type=self._get_kms_multi_region_key_type(key),
                    rotation_applicable=self._is_kms_rotation_status_applicable(key),
                    rotation_enabled=rotation_status_by_key_id.get(key_id),
                    tag_read_state=tag_read_state,
                    tag_count=tag_count,
                ),
            )
        return [
            KmsCostGovernanceRecord(
                account_id=self.account_id,
                region=region,
                listed_key_count=len(keys),
                key_count=len(key_details),
                inaccessible_key_count=len(inaccessible_key_ids),
                customer_managed_key_count=len(customer_keys),
                aws_managed_key_count=(described_aws_managed_key_count + len(skipped_aws_managed_alias_key_ids)),
                alias_classified_aws_managed_key_count=len(
                    skipped_aws_managed_alias_key_ids,
                ),
                enabled_customer_key_count=sum(1 for key in customer_keys if str(key.get("KeyState") or "").upper() == "ENABLED"),
                disabled_customer_key_count=sum(1 for key in customer_keys if str(key.get("KeyState") or "").upper() == "DISABLED"),
                pending_deletion_key_count=sum(1 for key in customer_keys if str(key.get("KeyState") or "").upper() == "PENDINGDELETION"),
                multi_region_key_count=sum(1 for key in customer_keys if bool(key.get("MultiRegion"))),
                multi_region_primary_key_count=sum(1 for key in customer_keys if self._get_kms_multi_region_key_type(key) == "PRIMARY"),
                multi_region_replica_key_count=sum(1 for key in customer_keys if self._get_kms_multi_region_key_type(key) == "REPLICA"),
                symmetric_key_count=sum(1 for key in customer_keys if self._is_kms_symmetric_key(key)),
                asymmetric_key_count=sum(1 for key in customer_keys if self._is_kms_asymmetric_key(key)),
                hmac_key_count=sum(1 for key in customer_keys if self._is_kms_hmac_key(key)),
                external_origin_key_count=sum(1 for key in customer_keys if str(key.get("Origin") or "").upper() == "EXTERNAL"),
                alias_count=len(aliases),
                customer_alias_count=sum(
                    1
                    for alias in aliases
                    if str(alias.get("AliasName") or "").startswith("alias/") and not str(alias.get("AliasName") or "").startswith("alias/aws/")
                ),
                sample_key_ids=[str(key.get("KeyId")) for key in customer_keys[:10] if key.get("KeyId")],
                sample_inaccessible_key_ids=sorted(dict.fromkeys(inaccessible_key_ids))[:10],
                sample_alias_classified_aws_managed_key_ids=sorted(
                    dict.fromkeys(skipped_aws_managed_alias_key_ids),
                )[:10],
                sample_alias_names=self._get_sample_kms_alias_names(aliases),
                sample_key_states=sorted(
                    {str(key.get("KeyState")) for key in customer_keys if key.get("KeyState")},
                ),
                sample_key_specs=self._get_sample_kms_values(
                    customer_keys,
                    "KeySpec",
                ),
                sample_key_usages=self._get_sample_kms_values(
                    customer_keys,
                    "KeyUsage",
                ),
                sample_key_origins=self._get_sample_kms_values(
                    customer_keys,
                    "Origin",
                ),
                sample_multi_region_key_types=self._get_sample_kms_multi_region_types(
                    customer_keys,
                ),
                sample_disabled_key_ids=[
                    str(key.get("KeyId")) for key in customer_keys[:10] if key.get("KeyId") and str(key.get("KeyState") or "").upper() == "DISABLED"
                ],
                sample_pending_deletion_key_ids=[
                    str(key.get("KeyId")) for key in customer_keys[:10] if key.get("KeyId") and str(key.get("KeyState") or "").upper() == "PENDINGDELETION"
                ],
                sample_rotation_disabled_key_ids=[key_id for key_id, enabled in list(rotation_status_by_key_id.items())[:10] if enabled is False],
                raw_keys=raw_keys,
                derived_policy_fields_populated=False,
                permission_errors=permission_errors,
            ),
        ]

    def _collect_secrets_manager_record(
        self,
        region: str,
    ) -> list[SecretsManagerCostGovernanceRecord]:
        client = self.session.create_client(
            "secretsmanager",
            region_name=region,
            audit_context=self.audit_context,
        )
        permission_errors: list[str] = []
        secrets = self._collect_secrets(client, permission_errors)
        active_secrets = [secret for secret in secrets if not secret.get("DeletedDate")]
        raw_secrets = [self._build_secret_evidence(secret) for secret in secrets]
        return [
            SecretsManagerCostGovernanceRecord(
                account_id=self.account_id,
                region=region,
                secret_count=len(secrets),
                active_secret_count=len(active_secrets),
                scheduled_deletion_secret_count=sum(1 for secret in secrets if bool(secret.get("DeletedDate"))),
                rotation_enabled_secret_count=sum(1 for secret in active_secrets if bool(secret.get("RotationEnabled"))),
                rotation_disabled_secret_count=sum(1 for secret in active_secrets if not bool(secret.get("RotationEnabled"))),
                missing_last_access_secret_count=sum(1 for secret in active_secrets if not secret.get("LastAccessedDate")),
                replica_secret_count=sum(1 for secret in active_secrets if bool(secret.get("ReplicationStatus"))),
                custom_kms_key_secret_count=sum(
                    1 for secret in active_secrets if bool(secret.get("KmsKeyId")) and "alias/aws/secretsmanager" not in str(secret.get("KmsKeyId") or "")
                ),
                service_managed_secret_count=sum(1 for secret in active_secrets if bool(secret.get("OwningService"))),
                customer_managed_secret_count=sum(1 for secret in active_secrets if not bool(secret.get("OwningService"))),
                rotation_lambda_secret_count=sum(1 for secret in active_secrets if bool(secret.get("RotationLambdaARN"))),
                sample_secret_names=self._get_sample_secret_names(active_secrets),
                sample_kms_key_ids=self._get_sample_secret_kms_key_ids(active_secrets),
                sample_rotation_disabled_secret_names=self._get_sample_secret_names(
                    [secret for secret in active_secrets if not bool(secret.get("RotationEnabled"))],
                ),
                sample_service_managed_secret_names=self._get_sample_secret_names(
                    [secret for secret in active_secrets if secret.get("OwningService")],
                ),
                sample_replica_regions=self._get_sample_secret_replica_regions(
                    active_secrets,
                ),
                raw_secrets=raw_secrets,
                derived_policy_fields_populated=False,
                permission_errors=permission_errors,
            ),
        ]

    def _build_secret_evidence(self, secret: dict[str, Any]) -> SecretEvidence:
        last_accessed = secret.get("LastAccessedDate")
        if isinstance(last_accessed, datetime) and last_accessed.tzinfo is None:
            last_accessed = last_accessed.replace(tzinfo=UTC)
        replica_regions = [
            str(replica.get("Region")) for replica in secret.get("ReplicationStatus", []) or [] if isinstance(replica, dict) and replica.get("Region")
        ]
        tags = secret.get("Tags")
        tag_count = len(tags) if isinstance(tags, list) else 0
        return SecretEvidence(
            name=str(secret.get("Name") or secret.get("ARN") or ""),
            scheduled_deletion=bool(secret.get("DeletedDate")),
            rotation_enabled=bool(secret.get("RotationEnabled")),
            last_accessed_at=(last_accessed if isinstance(last_accessed, datetime) else None),
            replica_regions=sorted(dict.fromkeys(replica_regions)),
            kms_key_id=(str(secret["KmsKeyId"]) if secret.get("KmsKeyId") else None),
            owning_service=(str(secret["OwningService"]) if secret.get("OwningService") else None),
            rotation_lambda_configured=bool(secret.get("RotationLambdaARN")),
            tag_read_state=("known_tagged" if tag_count else "known_untagged"),
            tag_count=tag_count,
        )

    def _collect_securityhub_summary(
        self,
        region: str,
        permission_errors: list[str],
    ) -> dict[str, Any]:
        client = self.session.create_client(
            "securityhub",
            region_name=region,
            audit_context=self.audit_context,
        )
        hub = self._safe_call(client, "describe_hub", {}, permission_errors)
        if hub is None:
            return {
                "enabled": False,
                "standard_count": 0,
                "ready_standard_count": 0,
                "non_ready_standard_count": 0,
                "standard_statuses": [],
                "sample_standard_arns": [],
            }
        standards = self._collect_securityhub_standards(client, permission_errors)
        status_values = self._get_securityhub_standard_statuses(standards)
        return {
            "enabled": True,
            "standard_count": len(standards),
            "ready_standard_count": sum(1 for standard in standards if str(standard.get("StandardsStatus") or "").upper() == "READY"),
            "non_ready_standard_count": sum(1 for standard in standards if str(standard.get("StandardsStatus") or "").upper() not in {"", "READY"}),
            "standard_statuses": status_values,
            "sample_standard_arns": [str(standard.get("StandardsArn")) for standard in standards[:10] if standard.get("StandardsArn")],
        }

    def _collect_securityhub_standards(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._pagination.collect_token_pages(
                client,
                "get_enabled_standards",
                result_key="StandardsSubscriptions",
            )
        except Exception as exc:  # noqa: BLE001
            self._append_collect_error("get_enabled_standards", exc, permission_errors)
            return []
        standards: list[dict[str, Any]] = []
        for page in result.pages:
            page_standards = page.get("StandardsSubscriptions", [])
            if isinstance(page_standards, list):
                standards.extend(page_standards)
        return standards
