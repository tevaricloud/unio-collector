# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, TypeVar

AuditRecordT = TypeVar("AuditRecordT")


class AuditResourceHelperMixin:  # noqa: D101
    def _has_change_trigger(self, rule: dict[str, Any]) -> bool:
        for detail in self._get_config_source_details(rule):
            message_type = str(detail.get("MessageType") or "")
            if message_type in {
                "ConfigurationItemChangeNotification",
                "OversizedConfigurationItemChangeNotification",
            }:
                return True
        return False

    def _get_config_source_details(
        self,
        rule: dict[str, Any],
    ) -> list[dict[str, Any]]:
        source = rule.get("Source")
        if not isinstance(source, dict):
            return []
        details = source.get("SourceDetails", [])
        if not isinstance(details, list):
            return []
        return [detail for detail in details if isinstance(detail, dict)]

    def _get_recorded_resource_types(
        self,
        recorder: dict[str, Any],
    ) -> list[str]:
        recording_group = recorder.get("recordingGroup", {})
        if not isinstance(recording_group, dict):
            return []
        resource_types = recording_group.get("resourceTypes", [])
        if not isinstance(resource_types, list):
            return []
        return [str(resource_type) for resource_type in resource_types]

    def _get_excluded_resource_types(
        self,
        recorder: dict[str, Any],
    ) -> list[str]:
        recording_group = recorder.get("recordingGroup", {})
        if not isinstance(recording_group, dict):
            return []
        exclusion = recording_group.get("exclusionByResourceTypes", {})
        if not isinstance(exclusion, dict):
            return []
        resource_types = exclusion.get("resourceTypes", [])
        if not isinstance(resource_types, list):
            return []
        return [str(resource_type) for resource_type in resource_types]

    def _get_recording_strategy_types(
        self,
        recorders: list[dict[str, Any]],
    ) -> list[str]:
        strategy_types: set[str] = set()
        for recorder in recorders:
            recording_group = recorder.get("recordingGroup", {})
            if not isinstance(recording_group, dict):
                continue
            strategy = recording_group.get("recordingStrategy", {})
            if not isinstance(strategy, dict):
                continue
            use_only = strategy.get("useOnly")
            if use_only:
                strategy_types.add(str(use_only))
        return sorted(strategy_types)

    def _get_sample_recorded_resource_types(
        self,
        recorders: list[dict[str, Any]],
    ) -> list[str]:
        resource_types: set[str] = set()
        for recorder in recorders:
            resource_types.update(self._get_recorded_resource_types(recorder))
        return sorted(resource_types)[:20]

    def _get_sample_excluded_resource_types(
        self,
        recorders: list[dict[str, Any]],
    ) -> list[str]:
        resource_types: set[str] = set()
        for recorder in recorders:
            resource_types.update(self._get_excluded_resource_types(recorder))
        return sorted(resource_types)[:20]

    def _collect_kms_key_refs(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._pagination.collect_token_pages(
                client,
                "list_keys",
                result_key="Keys",
                response_cursor_keys=("NextMarker", "Marker"),
                request_cursor_key="Marker",
            )
        except Exception as exc:  # noqa: BLE001
            self._append_collect_error("list_keys", exc, permission_errors)
            return []
        keys: list[dict[str, Any]] = []
        for page in result.pages:
            page_keys = page.get("Keys", [])
            if isinstance(page_keys, list):
                keys.extend(key for key in page_keys if isinstance(key, dict))
        return keys

    def _collect_kms_aliases(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._pagination.collect_token_pages(
                client,
                "list_aliases",
                result_key="Aliases",
                response_cursor_keys=("NextMarker", "Marker"),
                request_cursor_key="Marker",
            )
        except Exception as exc:  # noqa: BLE001
            self._append_collect_error("list_aliases", exc, permission_errors)
            return []
        aliases: list[dict[str, Any]] = []
        for page in result.pages:
            page_aliases = page.get("Aliases", [])
            if isinstance(page_aliases, list):
                aliases.extend(alias for alias in page_aliases if isinstance(alias, dict))
        return aliases

    def _collect_kms_key_metadata(
        self,
        client: Any,  # noqa: ANN401
        key: dict[str, Any],
        permission_errors: list[str],
    ) -> dict[str, Any] | None:
        key_id = str(key.get("KeyId") or key.get("KeyArn") or "")
        if not key_id:
            return None
        response = self._safe_call(
            client,
            "describe_key",
            {"KeyId": key_id},
            permission_errors,
        )
        metadata = response.get("KeyMetadata") if response else None
        return metadata if isinstance(metadata, dict) else None

    def _collect_kms_rotation_enabled(
        self,
        client: Any,  # noqa: ANN401
        key_id: str,
        permission_errors: list[str],
    ) -> bool | None:
        response = self._safe_call(
            client,
            "get_key_rotation_status",
            {"KeyId": key_id},
            permission_errors,
        )
        if not response:
            return None
        return bool(response.get("KeyRotationEnabled"))

    def _collect_kms_key_tags(
        self,
        client: Any,  # noqa: ANN401
        key_id: str,
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._pagination.collect_token_pages(
                client,
                "list_resource_tags",
                result_key="Tags",
                request_parameters={"KeyId": key_id},
                response_cursor_keys=("NextMarker", "Marker"),
                request_cursor_key="Marker",
            )
        except Exception as exc:  # noqa: BLE001
            self._append_collect_error(
                "list_resource_tags",
                exc,
                permission_errors,
            )
            return []
        tags: list[dict[str, Any]] = []
        for page in result.pages:
            page_tags = page.get("Tags", [])
            if isinstance(page_tags, list):
                tags.extend(tag for tag in page_tags if isinstance(tag, dict))
        return tags

    def _get_sample_kms_alias_names(
        self,
        aliases: list[dict[str, Any]],
    ) -> list[str]:
        names = [str(alias.get("AliasName")) for alias in aliases if alias.get("AliasName") and not str(alias.get("AliasName")).startswith("alias/aws/")]
        return sorted(dict.fromkeys(names))[:10]

    def _get_kms_aws_managed_alias_key_ids(
        self,
        aliases: list[dict[str, Any]],
    ) -> set[str]:
        return {str(alias.get("TargetKeyId")) for alias in aliases if alias.get("TargetKeyId") and str(alias.get("AliasName") or "").startswith("alias/aws/")}

    def _get_kms_customer_alias_key_ids(
        self,
        aliases: list[dict[str, Any]],
    ) -> set[str]:
        return {
            str(alias.get("TargetKeyId"))
            for alias in aliases
            if alias.get("TargetKeyId")
            and str(alias.get("AliasName") or "").startswith("alias/")
            and not str(alias.get("AliasName") or "").startswith("alias/aws/")
        }

    def _get_sample_kms_values(
        self,
        keys: list[dict[str, Any]],
        field_name: str,
    ) -> list[str]:
        values = [str(key.get(field_name)) for key in keys if key.get(field_name)]
        return sorted(dict.fromkeys(values))[:10]

    def _get_sample_kms_multi_region_types(
        self,
        keys: list[dict[str, Any]],
    ) -> list[str]:
        values = [key_type for key in keys if (key_type := self._get_kms_multi_region_key_type(key))]
        return sorted(dict.fromkeys(values))[:10]

    def _get_kms_multi_region_key_type(self, key: dict[str, Any]) -> str:
        config = key.get("MultiRegionConfiguration")
        if not isinstance(config, dict):
            return ""
        return str(config.get("MultiRegionKeyType") or "").upper()

    def _is_kms_symmetric_key(self, key: dict[str, Any]) -> bool:
        key_spec = str(key.get("KeySpec") or "").upper()
        return key_spec == "SYMMETRIC_DEFAULT"

    def _is_kms_asymmetric_key(self, key: dict[str, Any]) -> bool:
        key_spec = str(key.get("KeySpec") or "").upper()
        return key_spec.startswith(("RSA_", "ECC_", "SM2"))

    def _is_kms_hmac_key(self, key: dict[str, Any]) -> bool:
        return str(key.get("KeySpec") or "").upper().startswith("HMAC_")

    def _is_kms_rotation_status_applicable(self, key: dict[str, Any]) -> bool:
        return (
            self._is_kms_symmetric_key(key) and str(key.get("Origin") or "").upper() in {"", "AWS_KMS"} and str(key.get("KeyState") or "").upper() == "ENABLED"
        )

    def _collect_secrets(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._pagination.collect_token_pages(
                client,
                "list_secrets",
                result_key="SecretList",
                response_cursor_keys=("NextToken",),
                request_cursor_key="NextToken",
            )
        except Exception as exc:  # noqa: BLE001
            self._append_collect_error("list_secrets", exc, permission_errors)
            return []
        secrets: list[dict[str, Any]] = []
        for page in result.pages:
            page_secrets = page.get("SecretList", [])
            if isinstance(page_secrets, list):
                secrets.extend(secret for secret in page_secrets if isinstance(secret, dict))
        return secrets

    def _is_secret_last_access_before(
        self,
        secret: dict[str, Any],
        cutoff: datetime,
    ) -> bool:
        value = secret.get("LastAccessedDate")
        if not isinstance(value, datetime):
            return False
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value < cutoff

    def _get_sample_secret_names(
        self,
        secrets: list[dict[str, Any]],
    ) -> list[str]:
        names = [str(secret.get("Name")) for secret in secrets if secret.get("Name")]
        return sorted(dict.fromkeys(names))[:10]

    def _get_sample_secret_kms_key_ids(
        self,
        secrets: list[dict[str, Any]],
    ) -> list[str]:
        key_ids = [str(secret.get("KmsKeyId")) for secret in secrets if secret.get("KmsKeyId")]
        return sorted(dict.fromkeys(key_ids))[:10]

    def _get_sample_secret_replica_regions(
        self,
        secrets: list[dict[str, Any]],
    ) -> list[str]:
        regions: list[str] = []
        for secret in secrets:
            replication_status = secret.get("ReplicationStatus")
            if not isinstance(replication_status, list):
                continue
            regions.extend(str(item["Region"]) for item in replication_status if isinstance(item, dict) and item.get("Region"))
        return sorted(dict.fromkeys(regions))[:10]

    def get_available_regions(self) -> list[str]:  # noqa: D102
        if self._available_regions_cache is not None:
            return self._available_regions_cache
        if self.selected_regions:
            self._available_regions_cache = sorted(self.selected_regions)
            return self._available_regions_cache
        client = self.session.create_client(
            "ec2",
            region_name=self.session.get_region_name() or "us-east-1",
            audit_context=self.audit_context,
        )
        response = client.describe_regions(AllRegions=False)
        self._available_regions_cache = sorted(region["RegionName"] for region in response.get("Regions", []))
        return self._available_regions_cache
