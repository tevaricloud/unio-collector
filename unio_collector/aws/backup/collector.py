from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any, TypeVar

from unio_collector.aws.backup.details import BackupDetailCollectionMixin
from unio_collector.aws.backup.helpers import (
    build_backup_rule_records,
    get_backup_plan_arn,
    get_datetime_value,
    get_int_value,
    normalize_backup_selection_detail_mode,
)
from unio_collector.aws.backup.plan import BackupPlanRecord
from unio_collector.aws.backup.selection_detail import BackupSelectionDetailResult
from unio_collector.aws.backup.vault import BackupVaultRecord
from unio_collector.aws.collection import (
    AwsCollectionTask,
)
from unio_collector.aws.inventory_helpers import RegionalInventoryCollectionHelper
from unio_collector.aws.pagination import AwsPaginationHelper

if TYPE_CHECKING:
    from datetime import datetime

    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.backup.recovery_point import BackupRecoveryPointRecord

T = TypeVar("T")


class BackupInventoryCollector(BackupDetailCollectionMixin):  # noqa: D101
    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        selected_regions: list[str] | None = None,
        max_detail_workers: int | None = None,
        collect_tags: bool = True,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.selected_regions = selected_regions
        self.max_detail_workers = max(
            1,
            max_detail_workers or self._get_max_workers(),
        )
        self.collect_tags = collect_tags
        self._pagination = AwsPaginationHelper()
        self._regional_collection = RegionalInventoryCollectionHelper(
            self.session,
            account_id=self.account_id,
            audit_context=self.audit_context,
            collector_id="BackupInventoryCollector",
        )

    def collect_recovery_points(  # noqa: D102
        self,
        *,
        older_than_days: int | None = None,
        reference_time: datetime | None = None,
    ) -> list[BackupRecoveryPointRecord]:
        reference_time = self._resolve_reference_time(reference_time)
        created_before = self._build_created_before_filter(
            older_than_days,
            reference_time=reference_time,
        )
        return self._regional_collection.collect_region_records(
            regions=self.get_available_regions(),
            service="backup",
            operation="ListBackupVaults",
            collect_region=(
                lambda region: self._collect_recovery_points_in_region(
                    region,
                    created_before=created_before,
                    reference_time=reference_time,
                )
            ),
        )

    def collect_inventory_records(  # noqa: D102
        self,
        *,
        older_than_days: int | None = None,
        selection_detail_mode: object = "full",
        reference_time: datetime | None = None,
    ) -> list[object]:
        reference_time = self._resolve_reference_time(reference_time)
        created_before = self._build_created_before_filter(
            older_than_days,
            reference_time=reference_time,
        )
        detail_mode = normalize_backup_selection_detail_mode(selection_detail_mode)
        return self._regional_collection.collect_region_records(
            regions=self.get_available_regions(),
            service="backup",
            operation="ListBackupVaults",
            collect_region=(
                lambda region: self._collect_inventory_records_in_region(
                    region,
                    created_before=created_before,
                    selection_detail_mode=detail_mode,
                    reference_time=reference_time,
                )
            ),
        )

    def collect_governance_records(  # noqa: D102
        self,
        *,
        selection_detail_mode: object = "full",
    ) -> list[object]:
        detail_mode = normalize_backup_selection_detail_mode(selection_detail_mode)
        return self._regional_collection.collect_region_records(
            regions=self.get_available_regions(),
            service="backup",
            operation="ListBackupPlans",
            collect_region=(
                lambda region: self._collect_governance_records_in_region(
                    region,
                    selection_detail_mode=detail_mode,
                )
            ),
        )

    def _collect_inventory_records_in_region(
        self,
        region: str,
        *,
        created_before: datetime | None,
        selection_detail_mode: str,
        reference_time: datetime,
    ) -> list[object]:
        client = self.session.create_client(
            "backup",
            region_name=region,
            audit_context=self.audit_context,
        )
        records: list[object] = []
        vault_records, vault_names = self._collect_vault_records(client, region)
        records.extend(vault_records)
        records.extend(
            self._collect_plan_records(
                client,
                region,
                vault_names,
                selection_detail_mode=selection_detail_mode,
            ),
        )
        vault_point_tasks = [
            self._build_vault_points_task(
                client,
                region,
                vault.backup_vault_name,
                vault.backup_vault_arn,
                created_before=created_before,
                reference_time=reference_time,
            )
            for vault in vault_records
            if self._should_collect_vault_points(vault.recovery_point_count)
        ]
        for vault_points in self._run_detail_tasks(vault_point_tasks):
            records.extend(vault_points)
        return records

    def _collect_governance_records_in_region(
        self,
        region: str,
        *,
        selection_detail_mode: str,
    ) -> list[object]:
        client = self.session.create_client(
            "backup",
            region_name=region,
            audit_context=self.audit_context,
        )
        records: list[object] = []
        vault_records, vault_names = self._collect_vault_records(client, region)
        records.extend(vault_records)
        records.extend(
            self._collect_plan_records(
                client,
                region,
                vault_names,
                selection_detail_mode=selection_detail_mode,
            ),
        )
        return records

    def _collect_vault_records(
        self,
        client: Any,  # noqa: ANN401
        region: str,
    ) -> tuple[list[BackupVaultRecord], set[str]]:
        records: list[BackupVaultRecord] = []
        vault_names: set[str] = set()
        vault_pages = self._pagination.collect_token_pages(
            client,
            "list_backup_vaults",
            result_key="BackupVaultList",
            request_parameters={"MaxResults": 100},
        ).pages
        vaults: list[dict[str, Any]] = []
        for page in vault_pages:
            vaults.extend(vault for vault in page.get("BackupVaultList", []) if isinstance(vault, dict) and vault.get("BackupVaultName"))
        tasks = [
            AwsCollectionTask(
                name=(f"BackupInventoryCollector:vault:{region}:{vault.get('BackupVaultName')}"),
                scanner_id=self.audit_context.scanner_id,
                collector_id=self.audit_context.collector,
                account_id=self.account_id,
                region=region,
                service="backup",
                operation="BackupVaultMetadata",
                payload={"backup_vault_name": str(vault.get("BackupVaultName"))},
                collect=lambda vault=vault: self._collect_vault_record(
                    client,
                    region,
                    vault,
                ),
            )
            for vault in vaults
        ]
        for record in self._run_detail_tasks(tasks):
            records.append(record)
            vault_names.add(record.backup_vault_name)
        return records, vault_names

    def _collect_vault_record(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        vault: dict[str, Any],
    ) -> BackupVaultRecord:
        vault_name = str(vault.get("BackupVaultName") or "")
        vault_arn = str(vault.get("BackupVaultArn")) if vault.get("BackupVaultArn") is not None else None
        tags, tag_error = self._collect_tags(client, vault_arn)
        collection_errors = [tag_error] if tag_error else []
        return BackupVaultRecord(
            backup_vault_name=vault_name,
            backup_vault_arn=vault_arn,
            account_id=self.account_id,
            region=region,
            recovery_point_count=get_int_value(vault.get("NumberOfRecoveryPoints")),
            encryption_key_arn=(str(vault.get("EncryptionKeyArn")) if vault.get("EncryptionKeyArn") is not None else None),
            tags=tags,
            tags_collected=self.collect_tags,
            collection_errors=collection_errors,
        )

    def _collect_plan_records(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        vault_names: set[str],
        *,
        selection_detail_mode: str,
    ) -> list[BackupPlanRecord]:
        records: list[BackupPlanRecord] = []
        pages = self._pagination.collect_token_pages(
            client,
            "list_backup_plans",
            result_key="BackupPlansList",
            request_parameters={"MaxResults": 100},
        ).pages
        plan_summaries: list[dict[str, Any]] = []
        for page in pages:
            plan_summaries.extend(plan_summary for plan_summary in page.get("BackupPlansList", []) if isinstance(plan_summary, dict))
        tasks = []
        for plan_summary in plan_summaries:
            if not isinstance(plan_summary, dict):
                continue
            plan_id = str(plan_summary.get("BackupPlanId") or "")
            if not plan_id:
                continue
            tasks.append(
                AwsCollectionTask(
                    name=f"BackupInventoryCollector:plan:{region}:{plan_id}",
                    scanner_id=self.audit_context.scanner_id,
                    collector_id=self.audit_context.collector,
                    account_id=self.account_id,
                    region=region,
                    service="backup",
                    operation="BackupPlanMetadata",
                    payload={"backup_plan_id": plan_id},
                    collect=lambda plan_id=plan_id, plan_summary=plan_summary: self._collect_plan_record(
                        client,
                        region,
                        plan_id,
                        plan_summary,
                        vault_names,
                        selection_detail_mode=selection_detail_mode,
                    ),
                ),
            )
        records.extend(self._run_detail_tasks(tasks))
        return records

    def _collect_plan_record(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        plan_id: str,
        plan_summary: dict[str, Any],
        vault_names: set[str],
        *,
        selection_detail_mode: str,
    ) -> BackupPlanRecord:
        collection_errors: list[str] = []
        plan_detail = self._safe_call(
            client,
            "get_backup_plan",
            {"BackupPlanId": plan_id},
            collection_errors,
        )
        plan = plan_detail.get("BackupPlan", {}) if plan_detail else {}
        plan_arn = get_backup_plan_arn(plan_summary, plan_detail)
        tags, tag_error = self._collect_tags(client, plan_arn)
        if tag_error:
            collection_errors.append(tag_error)
        selection_summaries = self._collect_plan_selections(
            client,
            plan_id,
            collection_errors,
        )
        if selection_detail_mode == "summary":
            selection_details = [self._build_selection_summary_record(selection_summary) for selection_summary in selection_summaries]
            if selection_summaries:
                collection_errors.append(
                    "get_backup_selection skipped by configuration (selection_detail_mode=summary).",
                )
        else:
            selection_results = self._collect_selection_details(
                client,
                region,
                plan_id,
                selection_summaries,
            )
            selection_details = [selection_result.record for selection_result in selection_results]
            for selection_result in selection_results:
                collection_errors.extend(selection_result.collection_errors)
        return BackupPlanRecord(
            backup_plan_id=plan_id,
            backup_plan_arn=plan_arn,
            backup_plan_name=str(
                plan.get("BackupPlanName") or plan_summary.get("BackupPlanName") or plan_id,
            ),
            account_id=self.account_id,
            region=region,
            rules=build_backup_rule_records(plan, vault_names),
            selections=selection_details,
            tags=tags,
            tags_collected=self.collect_tags,
            creation_date=get_datetime_value(plan_summary.get("CreationDate")),
            last_execution_date=get_datetime_value(
                plan_summary.get("LastExecutionDate"),
            ),
            collection_errors=collection_errors,
        )

    def _collect_selection_details(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        plan_id: str,
        selection_summaries: list[dict[str, Any]],
    ) -> list[BackupSelectionDetailResult]:
        tasks: list[AwsCollectionTask[BackupSelectionDetailResult]] = []
        for selection_summary in selection_summaries:
            selection_id = str(selection_summary.get("SelectionId") or "")
            if not selection_id:
                continue
            tasks.append(
                AwsCollectionTask(
                    name=(f"BackupInventoryCollector:selection:{region}:{plan_id}:{selection_id}"),
                    scanner_id=self.audit_context.scanner_id,
                    collector_id=self.audit_context.collector,
                    account_id=self.account_id,
                    region=region,
                    service="backup",
                    operation="GetBackupSelection",
                    payload={
                        "backup_plan_id": plan_id,
                        "selection_id": selection_id,
                    },
                    collect=(
                        lambda selection_summary=selection_summary: self._collect_selection_detail_result(
                            client,
                            plan_id,
                            selection_summary,
                        )
                    ),
                ),
            )
        return self._run_detail_tasks(tasks)

    def _collect_selection_detail_result(
        self,
        client: Any,  # noqa: ANN401
        plan_id: str,
        selection_summary: dict[str, Any],
    ) -> BackupSelectionDetailResult:
        collection_errors: list[str] = []
        return BackupSelectionDetailResult(
            record=self._collect_selection_detail(
                client,
                plan_id,
                selection_summary,
                collection_errors,
            ),
            collection_errors=collection_errors,
        )
