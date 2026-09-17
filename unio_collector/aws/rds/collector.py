from __future__ import annotations  # noqa: D100

import sys
from datetime import UTC, datetime, time
from typing import TYPE_CHECKING, Any

from unio_collector.aws.cloudwatch.metric_collector import CloudWatchMetricCollector
from unio_collector.aws.collection import (
    AwsCollectionExecutor,
    AwsCollectionTask,
    AwsCollectionTaskResult,
    record_collection_results,
)
from unio_collector.aws.inventory_helpers import (
    AwsInventoryMetricHelper,
    RegionalInventoryCollectionHelper,
)
from unio_collector.aws.metric.context import MetricCollectionContext
from unio_collector.aws.metric.request import MetricRequest
from unio_collector.aws.pagination import AwsPaginationHelper
from unio_collector.aws.rds.helpers import tags_to_dict
from unio_collector.aws.rds.instance_record import RdsInstanceRecord
from unio_collector.aws.rds.snapshot.plan import (
    RDS_CLUSTER_SNAPSHOT_PLAN,
    RDS_DB_SNAPSHOT_PLAN,
    RdsSnapshotCollectionPlan,
)

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.metric.summary import MetricSummary
    from unio_collector.aws.rds.snapshot.candidate import RdsSnapshotCandidate
    from unio_collector.aws.rds.snapshot.record import RdsSnapshotRecord
    from unio_collector.core.scan.period import ScanPeriod


class RdsInventoryCollector:  # noqa: D101
    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        selected_regions: list[str] | None = None,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.selected_regions = selected_regions
        self._available_regions_cache: list[str] | None = None
        self._pagination = AwsPaginationHelper()
        self._metric_batches = AwsInventoryMetricHelper()
        self._tag_cache: dict[str, dict[str, str]] = {}
        self._regional_collection = RegionalInventoryCollectionHelper(
            self.session,
            account_id=self.account_id,
            audit_context=self.audit_context,
            collector_id="RdsInventoryCollector",
        )

    def collect_instances(self, scan_period: ScanPeriod) -> list[RdsInstanceRecord]:  # noqa: D102
        return self._regional_collection.collect_region_records(
            regions=self.get_available_regions(),
            service="rds",
            operation="DescribeDBInstances",
            collect_region=lambda region: self._collect_instances_in_region(
                region,
                scan_period,
            ),
        )

    def collect_snapshots(self) -> list[RdsSnapshotRecord]:  # noqa: D102
        now = datetime.now(UTC)
        return self._regional_collection.collect_region_records(
            regions=self.get_available_regions(),
            service="rds",
            operation="DescribeDBSnapshots+DescribeDBClusterSnapshots",
            collect_region=lambda region: self._collect_snapshots_in_region(
                region,
                now,
            ),
        )

    def _collect_instances_in_region(
        self,
        region: str,
        scan_period: ScanPeriod,
    ) -> list[RdsInstanceRecord]:
        records: list[RdsInstanceRecord] = []
        client = self.session.create_client(
            "rds",
            region_name=region,
            audit_context=self.audit_context,
        )
        metrics = self._build_metric_collector(
            self.session,
            region=region,
            audit_context=self.audit_context,
        )
        raw_instances = self._collect_raw_instances(client)
        metrics_by_instance = self._collect_metrics_for_instances(
            metrics,
            raw_instances,
            scan_period,
        )
        tags_by_arn = self._collect_tags_for_arns(
            client,
            region,
            [str(instance.get("DBInstanceArn") or "") for instance in raw_instances if instance.get("DBInstanceArn")],
        )
        for instance in raw_instances:
            identifier = instance["DBInstanceIdentifier"]
            arn = instance.get("DBInstanceArn")
            records.append(
                RdsInstanceRecord(
                    db_instance_identifier=identifier,
                    db_instance_class=instance.get("DBInstanceClass", "unknown"),
                    engine=instance.get("Engine", "unknown"),
                    status=instance.get("DBInstanceStatus", "unknown"),
                    account_id=self.account_id,
                    region=region,
                    arn=arn,
                    allocated_storage_gib=instance.get("AllocatedStorage"),
                    tags=tags_by_arn.get(str(arn or ""), {}),
                    metrics=metrics_by_instance.get(identifier, []),
                ),
            )
        return records

    def _build_metric_collector(
        self,
        session: Any,  # noqa: ANN401
        *,
        region: str,
        audit_context: AwsAuditContext,
    ) -> CloudWatchMetricCollector:
        facade = sys.modules.get("unio_collector.aws.rds")
        collector_class = getattr(facade, "CloudWatchMetricCollector", None)
        if collector_class is None:
            collector_class = CloudWatchMetricCollector
        return collector_class(
            session,
            region=region,
            audit_context=audit_context,
        )

    def _collect_raw_instances(self, client: Any) -> list[dict[str, Any]]:  # noqa: ANN401
        pages = self._pagination.collect_token_pages(
            client,
            "describe_db_instances",
            result_key="DBInstances",
            request_parameters={"MaxRecords": 100},
            request_cursor_key="Marker",
            response_cursor_keys=("Marker",),
        ).pages
        raw_instances: list[dict[str, Any]] = []
        for response in pages:
            raw_instances.extend(instance for instance in response.get("DBInstances", []) if isinstance(instance, dict))
        return raw_instances

    def _collect_snapshots_in_region(
        self,
        region: str,
        now: datetime,
    ) -> list[RdsSnapshotRecord]:
        client = self.session.create_client(
            "rds",
            region_name=region,
            audit_context=self.audit_context,
        )
        candidates = [
            *self._collect_manual_db_snapshot_candidates(
                client,
                region,
                now,
            ),
            *self._collect_manual_db_cluster_snapshot_candidates(
                client,
                region,
                now,
            ),
        ]
        tags_by_arn = self._collect_tags_for_arns(
            client,
            region,
            [candidate.snapshot_arn or "" for candidate in candidates],
        )
        return [candidate.convert_to_record(self.account_id, tags_by_arn) for candidate in candidates]

    def _collect_metrics_for_instances(
        self,
        collector: CloudWatchMetricCollector,
        instances: list[dict[str, Any]],
        scan_period: ScanPeriod,
    ) -> dict[str, list[MetricSummary]]:
        return self._metric_batches.collect_summaries_by_owner(
            collector=collector,
            records=instances,
            owner_key="DBInstanceIdentifier",
            build_requests=lambda instance: self._build_instance_metric_requests(
                str(instance.get("DBInstanceIdentifier") or ""),
                scan_period,
            ),
        )

    def _build_instance_metric_requests(
        self,
        identifier: str,
        scan_period: ScanPeriod,
    ) -> list[MetricRequest]:
        start_time = datetime.combine(
            scan_period.current_start_date,
            time.min,
            tzinfo=UTC,
        )
        end_time = datetime.combine(
            scan_period.current_end_exclusive,
            time.min,
            tzinfo=UTC,
        )
        dimensions = [{"Name": "DBInstanceIdentifier", "Value": identifier}]
        metric_specs = [
            ("CPUUtilization", "Average"),
            ("DatabaseConnections", "Average"),
            ("ReadIOPS", "Average"),
            ("WriteIOPS", "Average"),
            ("FreeStorageSpace", "Average"),
        ]
        return [
            MetricRequest(
                namespace="AWS/RDS",
                metric_name=metric_name,
                dimensions=dimensions,
                statistic=statistic,
                period=3600,
                start_time=start_time,
                end_time=end_time,
                collection_context=MetricCollectionContext.RDS_INSTANCE,
            )
            for metric_name, statistic in metric_specs
        ]

    def get_available_regions(self) -> list[str]:  # noqa: D102
        if self._available_regions_cache is not None:
            return self._available_regions_cache
        if self.selected_regions:
            self._available_regions_cache = sorted(self.selected_regions)
            return self._available_regions_cache
        self._available_regions_cache = sorted(
            self.session.get_available_regions("rds"),
        )
        return self._available_regions_cache

    def _collect_tags_for_arns(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        arns: list[str],
    ) -> dict[str, dict[str, str]]:
        unique_arns = sorted({arn for arn in arns if arn})
        cached_tags: dict[str, dict[str, str]] = {}
        missing_arns: list[str] = []
        for arn in unique_arns:
            cached = self._tag_cache.get(arn)
            if cached is None:
                missing_arns.append(arn)
            else:
                cached_tags[arn] = dict(cached)
        if not missing_arns:
            return cached_tags
        tasks = [
            AwsCollectionTask(
                name=f"RdsInventoryCollector:tags:{arn}",
                scanner_id=self.audit_context.scanner_id,
                collector_id=self.audit_context.collector,
                account_id=self.account_id,
                region=region,
                service="rds",
                operation="ListTagsForResource",
                payload={"resource_arn": arn},
                collect=lambda arn=arn: self._fetch_tags(client, arn),
            )
            for arn in missing_arns
        ]
        results = AwsCollectionExecutor(max_workers=self._get_max_workers()).run(tasks)
        record_collection_results(self.session, results)
        return {
            **cached_tags,
            **self._build_tags_by_arn_from_results(results),
        }

    def _fetch_tags(self, client: Any, arn: str) -> dict[str, str]:  # noqa: ANN401
        response = client.list_tags_for_resource(ResourceName=arn)
        tags = tags_to_dict(response.get("TagList", []))
        self._tag_cache[arn] = dict(tags)
        return tags

    def _build_tags_by_arn_from_results(
        self,
        results: list[AwsCollectionTaskResult[dict[str, str]]],
    ) -> dict[str, dict[str, str]]:
        tags_by_arn: dict[str, dict[str, str]] = {}
        for result in results:
            arn = str(result.task.payload.get("resource_arn") or "")
            if not arn:
                continue
            if result.status == "completed" and result.value is not None:
                tags_by_arn[arn] = dict(result.value)
            else:
                tags_by_arn[arn] = {}
        return tags_by_arn

    def _collect_manual_db_snapshot_candidates(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        now: datetime,
    ) -> list[RdsSnapshotCandidate]:
        return self._collect_manual_snapshot_candidates(
            client,
            region,
            now,
            plan=RDS_DB_SNAPSHOT_PLAN,
        )

    def _collect_manual_db_cluster_snapshot_candidates(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        now: datetime,
    ) -> list[RdsSnapshotCandidate]:
        return self._collect_manual_snapshot_candidates(
            client,
            region,
            now,
            plan=RDS_CLUSTER_SNAPSHOT_PLAN,
        )

    def _collect_manual_snapshot_candidates(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        now: datetime,
        *,
        plan: RdsSnapshotCollectionPlan,
    ) -> list[RdsSnapshotCandidate]:
        candidates: list[RdsSnapshotCandidate] = []
        pages = self._pagination.collect_token_pages(
            client,
            plan.operation_name,
            result_key=plan.result_key,
            request_parameters=plan.build_request_parameters(),
            request_cursor_key="Marker",
            response_cursor_keys=("Marker",),
        ).pages
        for page in pages:
            snapshots = page.get(plan.result_key, [])
            if not isinstance(snapshots, list):
                continue
            for snapshot in snapshots:
                if not isinstance(snapshot, dict):
                    continue
                candidate = plan.build_candidate(
                    snapshot=snapshot,
                    region=region,
                    now=now,
                )
                if candidate is not None:
                    candidates.append(candidate)
        return candidates

    def _get_max_workers(self) -> int:
        runtime_config = getattr(self.session, "runtime_config", None)
        configured = getattr(runtime_config, "max_workers", 4)
        if not isinstance(configured, int) or configured <= 0:
            return 4
        return min(16, configured)
