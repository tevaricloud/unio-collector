from __future__ import annotations  # noqa: D100

import sys
from datetime import UTC, datetime, time
from typing import TYPE_CHECKING, Any

from unio_collector.aws.cloudwatch.metric_collector import CloudWatchMetricCollector
from unio_collector.aws.inventory_helpers import (
    AwsInventoryMetricHelper,
    RegionalInventoryCollectionHelper,
)
from unio_collector.aws.load_balancer.constants import (
    LOAD_BALANCER_TAG_SKIP_REASON,
    LOAD_BALANCER_TARGET_HEALTH_SKIP_REASON,
)
from unio_collector.aws.load_balancer.helpers import (
    load_balancer_dimension,
    tags_to_dict,
)
from unio_collector.aws.load_balancer.options import (
    LoadBalancerCollectionOptions,
)
from unio_collector.aws.load_balancer.record import LoadBalancerRecord
from unio_collector.aws.load_balancer.target_health import TargetHealthSummary
from unio_collector.aws.metric.context import MetricCollectionContext
from unio_collector.aws.metric.request import MetricRequest
from unio_collector.aws.pagination import AwsPaginationHelper
from unio_collector.aws.response_admission import (
    iter_response_rows,
    require_complete_response,
    require_response_mapping,
    require_response_rows,
    require_response_string,
)

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.metric.summary import MetricSummary
    from unio_collector.core.scan.period import ScanPeriod


class LoadBalancerInventoryCollector:  # noqa: D101
    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        selected_regions: list[str] | None = None,
        collection_options: LoadBalancerCollectionOptions | None = None,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.selected_regions = selected_regions
        self.collection_options = collection_options or LoadBalancerCollectionOptions()
        self._available_regions_cache: list[str] | None = None
        self._pagination = AwsPaginationHelper()
        self._metric_batches = AwsInventoryMetricHelper()
        self._regional_collection = RegionalInventoryCollectionHelper(
            self.session,
            account_id=self.account_id,
            audit_context=self.audit_context,
            collector_id="LoadBalancerInventoryCollector",
        )

    def collect_load_balancers(  # noqa: D102
        self,
        scan_period: ScanPeriod,
    ) -> list[LoadBalancerRecord]:
        return self._regional_collection.collect_region_records(
            regions=self.get_available_regions(),
            service="elbv2",
            operation="DescribeLoadBalancers",
            collect_region=lambda region: self._collect_load_balancers_in_region(
                region,
                scan_period,
            ),
        )

    def _collect_load_balancers_in_region(
        self,
        region: str,
        scan_period: ScanPeriod,
    ) -> list[LoadBalancerRecord]:
        records: list[LoadBalancerRecord] = []
        client = self.session.create_client(
            "elbv2",
            region_name=region,
            audit_context=self.audit_context,
        )
        metrics = self._build_metric_collector(
            self.session,
            region=region,
            audit_context=self.audit_context,
        )
        raw_load_balancers = self._collect_raw_load_balancers(client)
        metrics_by_arn = self._collect_metrics_for_load_balancers(
            metrics,
            raw_load_balancers,
            scan_period,
        )
        for load_balancer in raw_load_balancers:
            arn = load_balancer["LoadBalancerArn"]
            errors: list[str] = []
            target_groups = self._collect_target_groups(client, arn, errors)
            target_health = self._collect_target_health_summaries(
                client,
                target_groups,
            )
            health_collected = self.collection_options.should_collect_target_health() and not errors and all(item.available for item in target_health)
            if any(not item.available for item in target_health):
                errors.append("DescribeTargetHealth:UnavailableEvidence")
            tag_errors: list[str] = []
            tags = self._collect_tags(client, arn, tag_errors)
            records.append(
                LoadBalancerRecord(
                    load_balancer_arn=arn,
                    load_balancer_name=load_balancer.get(
                        "LoadBalancerName",
                        "unknown",
                    ),
                    load_balancer_type=load_balancer.get("Type", "unknown"),
                    state=load_balancer.get("State", {}).get("Code", "unknown"),
                    account_id=self.account_id,
                    region=region,
                    target_group_count=len(target_groups),
                    registered_target_count=sum(item.registered_count for item in target_health),
                    healthy_target_count=sum(item.healthy_count for item in target_health),
                    target_health_detail_mode=(self.collection_options.target_health_detail_mode),
                    target_health_metadata_collected=health_collected,
                    target_health_skip_reason=(None if health_collected else "unavailable_evidence" if errors else LOAD_BALANCER_TARGET_HEALTH_SKIP_REASON),
                    tags=tags,
                    tags_collected=self.collection_options.collect_tags and not tag_errors,
                    tag_skip_reason=("unavailable_evidence" if tag_errors else None if self.collection_options.collect_tags else LOAD_BALANCER_TAG_SKIP_REASON),
                    metrics=metrics_by_arn.get(arn, []),
                    collection_errors=tuple(errors + tag_errors),
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
        facade = sys.modules.get("unio_collector.aws.load_balancer")
        collector_class = getattr(facade, "CloudWatchMetricCollector", None)
        if collector_class is None:
            collector_class = CloudWatchMetricCollector
        return collector_class(
            session,
            region=region,
            audit_context=audit_context,
        )

    def _collect_raw_load_balancers(self, client: Any) -> list[dict[str, Any]]:  # noqa: ANN401
        pages = self._pagination.collect_token_pages(
            client,
            "describe_load_balancers",
            result_key="LoadBalancers",
            request_parameters={"PageSize": 400},
            request_cursor_key="Marker",
            response_cursor_keys=("NextMarker",),
        ).pages
        raw_load_balancers: list[dict[str, Any]] = []
        for load_balancer in iter_response_rows(pages, "LoadBalancers"):
            require_response_string(load_balancer.get("LoadBalancerArn"))
            raw_load_balancers.append(load_balancer)
        return raw_load_balancers

    def _collect_metrics_for_load_balancers(
        self,
        collector: CloudWatchMetricCollector,
        load_balancers: list[dict[str, Any]],
        scan_period: ScanPeriod,
    ) -> dict[str, list[MetricSummary]]:
        return self._metric_batches.collect_summaries_by_owner(
            collector=collector,
            records=load_balancers,
            owner_key="LoadBalancerArn",
            build_requests=lambda load_balancer: self._build_metric_requests(
                load_balancer,
                scan_period,
            ),
        )

    def _build_metric_requests(
        self,
        load_balancer: dict[str, Any],
        scan_period: ScanPeriod,
    ) -> list[MetricRequest]:
        dimension_value = load_balancer_dimension(load_balancer)
        if not dimension_value:
            return []
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
        namespace = "AWS/ApplicationELB" if load_balancer.get("Type") == "application" else "AWS/NetworkELB"
        metric_specs = [
            ("RequestCount", "Sum"),
            ("ProcessedBytes", "Sum"),
            ("HealthyHostCount", "Average"),
            ("UnHealthyHostCount", "Average"),
        ]
        return [
            MetricRequest(
                namespace=namespace,
                metric_name=metric_name,
                dimensions=[{"Name": "LoadBalancer", "Value": dimension_value}],
                statistic=statistic,
                period=3600,
                start_time=start_time,
                end_time=end_time,
                collection_context=MetricCollectionContext.LOAD_BALANCER,
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
            self.session.get_available_regions("elbv2"),
        )
        return self._available_regions_cache

    def _collect_target_groups(self, client: Any, load_balancer_arn: str, errors: list[str] | None = None) -> list[str]:  # noqa: ANN401
        groups: list[str] = []
        try:
            response = client.describe_target_groups(LoadBalancerArn=load_balancer_arn)
            groups.extend(require_response_string(group.get("TargetGroupArn")) for group in require_response_rows(response, "TargetGroups"))
            require_complete_response(response)
        except Exception:  # noqa: BLE001
            if errors is not None:
                errors.append("DescribeTargetGroups:IncompleteEvidence")
        return groups

    def _collect_target_health(
        self,
        client: Any,  # noqa: ANN401
        target_group_arn: str,
    ) -> TargetHealthSummary:
        try:
            response = client.describe_target_health(TargetGroupArn=target_group_arn)
            descriptions = require_response_rows(response, "TargetHealthDescriptions")
            states = [require_response_string(require_response_mapping(item.get("TargetHealth")).get("State")) for item in descriptions]
        except Exception:  # noqa: BLE001
            return TargetHealthSummary(registered_count=0, healthy_count=0, available=False)
        return TargetHealthSummary(
            registered_count=len(descriptions),
            healthy_count=states.count("healthy"),
        )

    def _collect_target_health_summaries(
        self,
        client: Any,  # noqa: ANN401
        target_groups: list[str],
    ) -> list[TargetHealthSummary]:
        if not self.collection_options.should_collect_target_health():
            return []
        return [self._collect_target_health(client, target_group_arn) for target_group_arn in target_groups]

    def _collect_tags(self, client: Any, arn: str, errors: list[str] | None = None) -> dict[str, str]:  # noqa: ANN401
        if not self.collection_options.collect_tags:
            return {}
        try:
            response = client.describe_tags(ResourceArns=[arn])
            descriptions = require_response_rows(response, "TagDescriptions")
            matching = next(item for item in descriptions if item.get("ResourceArn") == arn)
            tags = require_response_rows(matching, "Tags")
        except Exception:  # noqa: BLE001
            if errors is not None:
                errors.append("DescribeTags:UnavailableEvidence")
            return {}
        return tags_to_dict(tags)
