# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar

from unio_collector.aws.backup.helpers import (
    get_calculated_delete_at,
    get_calculated_retention_days,
    get_datetime_value,
    get_int_value,
    get_string_list,
)
from unio_collector.aws.backup.recovery_point import BackupRecoveryPointRecord
from unio_collector.aws.backup.selection import BackupSelectionRecord
from unio_collector.aws.collection import (
    AwsCollectionExecutor,
    AwsCollectionTask,
    record_collection_results,
)

T = TypeVar("T")


class BackupDetailCollectionMixin:  # noqa: D101
    def _build_selection_summary_record(
        self,
        selection_summary: dict[str, Any],
    ) -> BackupSelectionRecord:
        selection_id = str(selection_summary.get("SelectionId") or "")
        return BackupSelectionRecord(
            selection_id=selection_id,
            selection_name=str(
                selection_summary.get("SelectionName") or selection_summary.get("BackupSelectionName") or selection_id,
            ),
            iam_role_arn=(str(selection_summary.get("IamRoleArn")) if selection_summary.get("IamRoleArn") is not None else None),
            resources=[],
            not_resources=[],
            conditions={},
            list_of_tags=[],
            creation_date=get_datetime_value(selection_summary.get("CreationDate")),
        )

    def _collect_plan_selections(
        self,
        client: Any,  # noqa: ANN401
        plan_id: str,
        collection_errors: list[str],
    ) -> list[dict[str, Any]]:
        pages = self._safe_token_pages(
            client,
            "list_backup_selections",
            result_key="BackupSelectionsList",
            request_parameters={
                "BackupPlanId": plan_id,
                "MaxResults": 100,
            },
            collection_errors=collection_errors,
        )
        selections: list[dict[str, Any]] = []
        for page in pages:
            selections.extend(item for item in page.get("BackupSelectionsList", []) if isinstance(item, dict))
        return selections

    def _collect_selection_detail(
        self,
        client: Any,  # noqa: ANN401
        plan_id: str,
        selection_summary: dict[str, Any],
        collection_errors: list[str],
    ) -> BackupSelectionRecord:
        selection_id = str(selection_summary.get("SelectionId") or "")
        response = self._safe_call(
            client,
            "get_backup_selection",
            {
                "BackupPlanId": plan_id,
                "SelectionId": selection_id,
            },
            collection_errors,
        )
        selection = response.get("BackupSelection", {}) if response else {}
        return BackupSelectionRecord(
            selection_id=selection_id,
            selection_name=str(
                selection.get("SelectionName") or selection_summary.get("SelectionName") or selection_id,
            ),
            iam_role_arn=(str(selection.get("IamRoleArn")) if selection.get("IamRoleArn") is not None else None),
            resources=get_string_list(selection.get("Resources")),
            not_resources=get_string_list(selection.get("NotResources")),
            conditions=dict(selection.get("Conditions") or {}),
            list_of_tags=list(selection.get("ListOfTags") or []),
            creation_date=get_datetime_value(selection_summary.get("CreationDate")),
        )

    def _collect_recovery_points_in_region(
        self,
        region: str,
        *,
        reference_time: datetime,
        created_before: datetime | None = None,
    ) -> list[BackupRecoveryPointRecord]:
        records: list[BackupRecoveryPointRecord] = []
        client = self.session.create_client(
            "backup",
            region_name=region,
            audit_context=self.audit_context,
        )
        vault_pages = self._pagination.collect_token_pages(
            client,
            "list_backup_vaults",
            result_key="BackupVaultList",
            request_parameters={"MaxResults": 100},
        ).pages
        tasks = []
        for page in vault_pages:
            for vault in page.get("BackupVaultList", []):
                vault_name = vault.get("BackupVaultName")
                if not vault_name:
                    continue
                if not self._should_collect_vault_points(
                    get_int_value(vault.get("NumberOfRecoveryPoints")),
                ):
                    continue
                tasks.append(
                    self._build_vault_points_task(
                        client,
                        region,
                        str(vault_name),
                        vault.get("BackupVaultArn"),
                        created_before=created_before,
                        reference_time=reference_time,
                    ),
                )
        for vault_points in self._run_detail_tasks(tasks):
            records.extend(vault_points)
        return records

    def _should_collect_vault_points(self, recovery_point_count: int | None) -> bool:
        return recovery_point_count is None or recovery_point_count > 0

    def get_available_regions(self) -> list[str]:  # noqa: D102
        if self.selected_regions:
            return sorted(self.selected_regions)
        return sorted(self.session.get_available_regions("backup"))

    def _collect_vault_points(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        vault_name: str,
        vault_arn: object,
        *,
        reference_time: datetime,
        created_before: datetime | None = None,
    ) -> list[BackupRecoveryPointRecord]:
        records: list[BackupRecoveryPointRecord] = []
        request_parameters: dict[str, Any] = {
            "BackupVaultName": vault_name,
            "MaxResults": 100,
        }
        if created_before is not None:
            request_parameters["ByCreatedBefore"] = created_before
        pages = self._pagination.collect_token_pages(
            client,
            "list_recovery_points_by_backup_vault",
            result_key="RecoveryPoints",
            request_parameters=request_parameters,
        ).pages
        for response in pages:
            for point in response.get("RecoveryPoints", []):
                created = point.get("CreationDate")
                age_days = None
                if isinstance(created, datetime):
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=UTC)
                    age_days = max((reference_time - created).days, 0)
                records.append(
                    BackupRecoveryPointRecord(
                        recovery_point_arn=point.get("RecoveryPointArn", "unknown"),
                        backup_vault_name=vault_name,
                        backup_vault_arn=(str(vault_arn) if vault_arn is not None else None),
                        account_id=self.account_id,
                        region=region,
                        resource_arn=point.get("ResourceArn"),
                        resource_type=point.get("ResourceType"),
                        resource_name=point.get("ResourceName"),
                        status=point.get("Status"),
                        backup_size_bytes=point.get("BackupSizeInBytes"),
                        creation_date=created if isinstance(created, datetime) else None,
                        completion_date=(point.get("CompletionDate") if isinstance(point.get("CompletionDate"), datetime) else None),
                        calculated_delete_at=get_calculated_delete_at(point),
                        calculated_retention_days=get_calculated_retention_days(
                            point,
                            created,
                        ),
                        age_days=age_days,
                    ),
                )
        return records

    def _build_vault_points_task(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        vault_name: str,
        vault_arn: object,
        *,
        created_before: datetime | None,
        reference_time: datetime,
    ) -> AwsCollectionTask[list[BackupRecoveryPointRecord]]:
        return AwsCollectionTask(
            name=f"BackupInventoryCollector:recovery-points:{region}:{vault_name}",
            scanner_id=self.audit_context.scanner_id,
            collector_id=self.audit_context.collector,
            account_id=self.account_id,
            region=region,
            service="backup",
            operation="ListRecoveryPointsByBackupVault",
            payload={"backup_vault_name": vault_name},
            collect=lambda: self._collect_vault_points(
                client,
                region,
                vault_name,
                vault_arn,
                created_before=created_before,
                reference_time=reference_time,
            ),
        )

    def _run_detail_tasks(
        self,
        tasks: list[AwsCollectionTask[T]],
    ) -> list[T]:
        results = AwsCollectionExecutor(max_workers=self.max_detail_workers).run(tasks)
        record_collection_results(self.session, results)
        return [result.value for result in results if result.status == "completed" and result.value is not None]

    def _safe_call(
        self,
        client: Any,  # noqa: ANN401
        operation_name: str,
        request_parameters: dict[str, Any],
        collection_errors: list[str],
    ) -> dict[str, Any]:
        try:
            operation = getattr(client, operation_name)
            response = operation(**request_parameters)
        except Exception as exc:  # noqa: BLE001
            collection_errors.append(f"{operation_name}:{exc}")
            return {}
        return response if isinstance(response, dict) else {}

    def _safe_token_pages(
        self,
        client: Any,  # noqa: ANN401
        operation_name: str,
        *,
        result_key: str,
        request_parameters: dict[str, Any],
        collection_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            return self._pagination.collect_token_pages(
                client,
                operation_name,
                result_key=result_key,
                request_parameters=request_parameters,
            ).pages
        except Exception as exc:  # noqa: BLE001
            collection_errors.append(f"{operation_name}:{exc}")
            return []

    def _collect_tags(
        self,
        client: Any,  # noqa: ANN401
        resource_arn: str | None,
    ) -> tuple[dict[str, str], str | None]:
        if not self.collect_tags:
            return {}, None
        if not resource_arn:
            return {}, "list_tags:resource_arn_unavailable"
        try:
            response = client.list_tags(ResourceArn=resource_arn)
        except Exception as exc:  # noqa: BLE001
            return {}, f"list_tags:{exc}"
        tags = response.get("Tags") if isinstance(response, dict) else {}
        if not isinstance(tags, dict):
            return {}, None
        return {str(key): str(value) for key, value in tags.items() if value is not None}, None

    def _build_created_before_filter(
        self,
        older_than_days: int | None,
        *,
        reference_time: datetime,
    ) -> datetime | None:
        if older_than_days is None or older_than_days <= 0:
            return None
        return reference_time - timedelta(days=older_than_days)

    def _resolve_reference_time(self, reference_time: datetime | None) -> datetime:
        if reference_time is None:
            return datetime.now(UTC)
        if reference_time.tzinfo is None:
            return reference_time.replace(tzinfo=UTC)
        return reference_time.astimezone(UTC)

    def _get_max_workers(self) -> int:
        runtime_config = getattr(self.session, "runtime_config", None)
        value = getattr(runtime_config, "max_workers", None)
        return value if isinstance(value, int) and value > 0 else 1
