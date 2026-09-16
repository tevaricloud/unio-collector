# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError

from unio_collector.aws.cloudfront.helpers import (
    build_metric_collection_reason,
    calculate_average,
    resolve_metric_collection_status,
)
from unio_collector.aws.cloudfront.metric_summary import CloudFrontMetricSummary
from unio_collector.aws.errors import get_aws_error_code

CLOUDFRONT_CONTROL_PLANE_REGION = "us-east-1"
CLOUDFRONT_METRIC_REGION_DIMENSION = "Global"
CLOUDFRONT_METRIC_PERIOD_SECONDS = 86400
MAX_CLOUDWATCH_METRIC_QUERIES = 500
MAX_INVALIDATION_DISTRIBUTIONS = 50
MIN_ELB_HOSTNAME_LABELS_BEFORE_AWS_SUFFIX = 3


class CloudFrontMetricMixin:  # noqa: D101
    def _build_empty_invalidation_summary(self) -> dict[str, Any]:
        return {
            "invalidation_distribution_count": 0,
            "invalidation_batch_count": 0,
            "invalidation_path_count": 0,
            "wildcard_invalidation_path_count": 0,
            "recent_invalidation_batch_count": 0,
            "recent_invalidation_path_count": 0,
            "recent_wildcard_invalidation_path_count": 0,
            "sample_invalidation_distribution_ids": [],
            "invalidation_collection_errors": [],
            "invalidation_path_evidence_complete": True,
            "invalidation_collection_limited": False,
        }

    def _collect_invalidation_summary(
        self,
        client: Any,  # noqa: ANN401
        distributions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        invalidation_distribution_ids: list[str] = []
        invalidation_batch_count = 0
        invalidation_path_count = 0
        wildcard_invalidation_path_count = 0
        recent_invalidation_batch_count = 0
        recent_invalidation_path_count = 0
        recent_wildcard_invalidation_path_count = 0
        invalidation_collection_errors: list[str] = []
        invalidation_path_evidence_complete = True
        distribution_ids = [str(item.get("Id")) for item in distributions if item.get("Id")][:MAX_INVALIDATION_DISTRIBUTIONS]
        for distribution_id in distribution_ids:
            try:
                invalidations = self._collect_distribution_invalidations(
                    client,
                    distribution_id,
                )
            except ClientError as exc:
                code = get_aws_error_code(exc) or exc.__class__.__name__
                invalidation_collection_errors.append(str(code))
                continue
            if invalidations:
                invalidation_distribution_ids.append(distribution_id)
            invalidation_batch_count += len(invalidations)
            for invalidation in invalidations:
                paths = self._get_invalidation_paths(invalidation)
                if paths is None:
                    invalidation_path_evidence_complete = False
                    paths = []
                invalidation_path_count += len(paths)
                wildcard_invalidation_path_count += sum(1 for path in paths if "*" in path)
                if self._is_invalidation_in_scan_period(invalidation):
                    recent_invalidation_batch_count += 1
                    recent_invalidation_path_count += len(paths)
                    recent_wildcard_invalidation_path_count += sum(1 for path in paths if "*" in path)
        return {
            "invalidation_distribution_count": len(invalidation_distribution_ids),
            "invalidation_batch_count": invalidation_batch_count,
            "invalidation_path_count": invalidation_path_count,
            "wildcard_invalidation_path_count": (wildcard_invalidation_path_count),
            "recent_invalidation_batch_count": recent_invalidation_batch_count,
            "recent_invalidation_path_count": recent_invalidation_path_count,
            "recent_wildcard_invalidation_path_count": (recent_wildcard_invalidation_path_count),
            "sample_invalidation_distribution_ids": (invalidation_distribution_ids[:10]),
            "invalidation_collection_errors": sorted(
                set(invalidation_collection_errors),
            ),
            "invalidation_path_evidence_complete": invalidation_path_evidence_complete,
            "invalidation_collection_limited": len(distributions) > len(distribution_ids),
        }

    def _collect_distribution_invalidations(
        self,
        client: Any,  # noqa: ANN401
        distribution_id: str,
    ) -> list[dict[str, Any]]:
        return self._marker_paginator.collect_items(
            client,
            "list_invalidations",
            list_key="InvalidationList",
            request_parameters={"DistributionId": distribution_id},
        )

    def _get_invalidation_paths(self, invalidation: dict[str, Any]) -> list[str] | None:
        batch = invalidation.get("InvalidationBatch")
        if not isinstance(batch, dict):
            return None
        paths = batch.get("Paths")
        if not isinstance(paths, dict):
            return None
        items = paths.get("Items", [] if paths.get("Quantity") == 0 else None)
        if not isinstance(items, list) or any(not isinstance(item, str) or not item for item in items):
            return None
        if "Quantity" in paths and (type(paths["Quantity"]) is not int or paths["Quantity"] != len(items)):
            return None
        return items

    def _is_invalidation_in_scan_period(
        self,
        invalidation: dict[str, Any],
    ) -> bool:
        if self.scan_period is None:
            return False
        created_at = self._parse_invalidation_created_at(invalidation)
        if created_at is None:
            return False
        return self.scan_period.current_start_datetime <= created_at < self.scan_period.current_end_exclusive_datetime

    def _parse_invalidation_created_at(
        self,
        invalidation: dict[str, Any],
    ) -> datetime | None:
        value = invalidation.get("CreateTime") or invalidation.get("CreatedTime")
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=UTC)
            return value.astimezone(UTC)
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value)
            except ValueError:
                return None
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC)
        return None

    def _collect_distribution_metric_summary(
        self,
        distributions: list[dict[str, Any]],
    ) -> CloudFrontMetricSummary:
        if not self.collect_metrics:
            return CloudFrontMetricSummary(
                metric_collection_status="skipped_by_chargeable_policy",
                metric_collection_reason=(
                    "CloudFront request, transfer, and error-rate metric "
                    "enrichment uses CloudWatch GetMetricData and was skipped "
                    "because optional metric enrichment was not enabled for "
                    "this scan."
                ),
            )
        if self.scan_period is None:
            return CloudFrontMetricSummary(
                metric_collection_status="not_configured",
                metric_collection_reason=("CloudFront metric enrichment requires a resolved scan period, but no scan period was available."),
            )
        if not distributions:
            return CloudFrontMetricSummary(
                metric_collection_status="not_applicable",
                metric_collection_reason=("No CloudFront distributions were visible to request metric context for this scan."),
            )
        distribution_ids = [str(item.get("Id")) for item in distributions if item.get("Id")]
        if not distribution_ids:
            return CloudFrontMetricSummary(
                metric_collection_status="not_applicable",
                metric_collection_reason=("Visible CloudFront distributions did not include distribution IDs for metric lookup."),
            )
        client = self.session.create_client(
            "cloudwatch",
            region_name=CLOUDFRONT_CONTROL_PLANE_REGION,
            audit_context=self.audit_context,
        )
        query_batches = self._build_metric_query_batches(distribution_ids)
        values_by_metric: dict[str, list[float]] = {
            "Requests": [],
            "BytesDownloaded": [],
            "BytesUploaded": [],
            "4xxErrorRate": [],
            "5xxErrorRate": [],
        }
        distribution_ids_with_metrics: set[str] = set()
        metric_collection_errors: list[str] = []
        query_to_metric: dict[str, tuple[str, str]] = {}
        for batch in query_batches:
            query_to_metric.update(batch["query_to_metric"])
            try:
                self._collect_metric_batch(
                    client,
                    batch["queries"],
                    query_to_metric,
                    values_by_metric,
                    distribution_ids_with_metrics,
                )
            except ClientError as exc:
                code = get_aws_error_code(exc) or exc.__class__.__name__
                metric_collection_errors.append(str(code))
            except Exception as exc:  # noqa: BLE001
                metric_collection_errors.append(exc.__class__.__name__)
        datapoint_count = sum(len(values) for values in values_by_metric.values())
        return CloudFrontMetricSummary(
            metric_collection_status=resolve_metric_collection_status(
                datapoint_count=datapoint_count,
                errors=metric_collection_errors,
            ),
            metric_collection_reason=build_metric_collection_reason(
                datapoint_count=datapoint_count,
                errors=metric_collection_errors,
            ),
            metric_distribution_count=len(distribution_ids_with_metrics),
            metric_datapoint_count=datapoint_count,
            request_sum=int(sum(values_by_metric["Requests"])),
            bytes_downloaded_sum=int(sum(values_by_metric["BytesDownloaded"])),
            bytes_uploaded_sum=int(sum(values_by_metric["BytesUploaded"])),
            four_xx_error_rate_average=calculate_average(
                values_by_metric["4xxErrorRate"],
            ),
            five_xx_error_rate_average=calculate_average(
                values_by_metric["5xxErrorRate"],
            ),
            metric_collection_errors=sorted(set(metric_collection_errors)),
        )

    def _build_metric_query_batches(
        self,
        distribution_ids: list[str],
    ) -> list[dict[str, Any]]:
        queries: list[dict[str, Any]] = []
        query_to_metric: dict[str, tuple[str, str]] = {}
        batches: list[dict[str, Any]] = []
        metric_specs = (
            ("Requests", "Sum"),
            ("BytesDownloaded", "Sum"),
            ("BytesUploaded", "Sum"),
            ("4xxErrorRate", "Average"),
            ("5xxErrorRate", "Average"),
        )
        query_index = 0
        for distribution_id in distribution_ids:
            for metric_name, statistic in metric_specs:
                query_id = f"m{query_index}"
                queries.append(
                    {
                        "Id": query_id,
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/CloudFront",
                                "MetricName": metric_name,
                                "Dimensions": [
                                    {
                                        "Name": "DistributionId",
                                        "Value": distribution_id,
                                    },
                                    {
                                        "Name": "Region",
                                        "Value": (CLOUDFRONT_METRIC_REGION_DIMENSION),
                                    },
                                ],
                            },
                            "Period": CLOUDFRONT_METRIC_PERIOD_SECONDS,
                            "Stat": statistic,
                        },
                        "ReturnData": True,
                    },
                )
                query_to_metric[query_id] = (distribution_id, metric_name)
                query_index += 1
                if len(queries) >= MAX_CLOUDWATCH_METRIC_QUERIES:
                    batches.append(
                        {
                            "queries": queries,
                            "query_to_metric": query_to_metric,
                        },
                    )
                    queries = []
                    query_to_metric = {}
        if queries:
            batches.append({"queries": queries, "query_to_metric": query_to_metric})
        return batches

    def _collect_metric_batch(
        self,
        client: Any,  # noqa: ANN401
        queries: list[dict[str, Any]],
        query_to_metric: dict[str, tuple[str, str]],
        values_by_metric: dict[str, list[float]],
        distribution_ids_with_metrics: set[str],
    ) -> None:
        if self.scan_period is None:
            return
        request: dict[str, Any] = {
            "MetricDataQueries": queries,
            "StartTime": self.scan_period.current_start_datetime,
            "EndTime": self.scan_period.current_end_exclusive_datetime,
            "ScanBy": "TimestampAscending",
        }
        while True:
            response = client.get_metric_data(**request)
            for result in response.get("MetricDataResults", []):
                if not isinstance(result, dict):
                    continue
                query_id = str(result.get("Id") or "")
                metric_context = query_to_metric.get(query_id)
                if not metric_context:
                    continue
                distribution_id, metric_name = metric_context
                values = [float(value) for value in result.get("Values", []) if isinstance(value, (int, float))]
                if not values:
                    continue
                distribution_ids_with_metrics.add(distribution_id)
                values_by_metric.setdefault(metric_name, []).extend(values)
            next_token = response.get("NextToken")
            if not next_token:
                break
            request["NextToken"] = next_token

    def _get_nested_quantity(
        self,
        distribution: dict[str, Any],
        key: str,
    ) -> int:
        value = distribution.get(key, {})
        if not isinstance(value, dict):
            return 0
        quantity = value.get("Quantity", 0)
        return int(quantity) if isinstance(quantity, int) else 0

    def _count_origins(
        self,
        distribution: dict[str, Any],
        *,
        origin_type: str,
    ) -> int:
        origins = self._get_origin_items(distribution)
        if origin_type == "custom":
            return sum(1 for origin in origins if "CustomOriginConfig" in origin)
        if origin_type == "s3":
            return sum(1 for origin in origins if "S3OriginConfig" in origin)
        return 0

    def _count_origin_domains(
        self,
        distribution: dict[str, Any],
        origin_type: str,
    ) -> int:
        return sum(1 for origin in self._get_origin_items(distribution) if self._classify_origin_domain(str(origin.get("DomainName") or "")) == origin_type)

    def _classify_origin_domain(self, domain_name: str) -> str:
        normalized = domain_name.strip().lower()
        if not normalized:
            return "unknown"
        if ".execute-api." in normalized:
            return "api_gateway"
        aws_suffix = next(
            (suffix for suffix in ("amazonaws.com.cn", "amazonaws.com") if normalized.endswith(f".{suffix}")),
            None,
        )
        if aws_suffix is not None:
            aws_labels = normalized[: -(len(aws_suffix) + 1)].split(".")
            if len(aws_labels) >= MIN_ELB_HOSTNAME_LABELS_BEFORE_AWS_SUFFIX and (aws_labels[-1] == "elb" or aws_labels[-2] == "elb"):
                return "load_balancer"
        if ".s3-website" in normalized:
            return "s3_website"
        if ".s3." in normalized or normalized.endswith(".s3.amazonaws.com"):
            return "s3_rest"
        if normalized.endswith(".amazonaws.com"):
            return "aws_service"
        return "custom_domain"

    def _count_origin_shield_enabled(
        self,
        distribution: dict[str, Any],
    ) -> int:
        return sum(1 for origin in self._get_origin_items(distribution) if bool(origin.get("OriginShield", {}).get("Enabled")))

    def _count_cache_behaviors_with_key(
        self,
        distribution: dict[str, Any],
        key: str,
    ) -> int:
        return self._count_cache_behaviors_matching(
            distribution,
            lambda behavior: bool(behavior.get(key)),
        )

    def _count_legacy_forwarded_values_behaviors(
        self,
        distribution: dict[str, Any],
    ) -> int:
        return self._count_cache_behaviors_matching(
            distribution,
            lambda behavior: isinstance(behavior.get("ForwardedValues"), dict),
        )
