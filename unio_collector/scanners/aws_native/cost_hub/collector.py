from __future__ import annotations  # noqa: D100

from functools import partial
from typing import TYPE_CHECKING, Any

from unio_collector.aws_native_recommendations.recommendation.record import (
    AwsNativeRecommendationRecord,
)
from unio_collector.scanners.aws_native.collection.coordinator import AwsNativeCollectionCoordinator
from unio_collector.scanners.aws_native.collection.normalization import (
    MAX_NATIVE_RECOMMENDATION_RECORDS,
    compact_dict,
    extract_estimated_savings,
    first_text,
    get_dict,
)
from unio_collector.scanners.aws_native.collection.reader import AwsNativeOperationReader
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class CostOptimizationHubRecommendationReviewCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    def collect(self, context: ScannerContext) -> dict[str, Any]:
        """Collect bounded provider facts before private recommendation analysis."""
        regions = self.get_regions(context)
        collection = AwsNativeCollectionCoordinator("cost_optimization_hub")
        for region in regions:
            client = self.create_client(context, region)
            collection.operation(
                client,
                operation="list_recommendation_summaries",
                result_keys=("items", "recommendationSummaries", "RecommendationSummaries"),
                parameters={"groupBy": "ResourceType"},
                region=region,
                label="Cost Optimization Hub summaries",
            )
            collection.operation(
                client,
                operation="list_recommendations",
                result_keys=("items", "recommendations", "Recommendations"),
                region=region,
                label="Cost Optimization Hub recommendations",
                normalize=partial(self.normalize_hub_record, region=region),
            )
            if collection.stop_recommendations:
                if collection.record_limit_reached:
                    collection.warnings.append(
                        f"Cost Optimization Hub recommendation ingestion was capped at {MAX_NATIVE_RECOMMENDATION_RECORDS} records for this scan."
                    )
                break
        if not regions:
            collection.unavailable(region="none", operation="endpoint_resolution", status="unsupported_region", code="NoSupportedEndpointRegion")
            collection.warnings.append("Cost Optimization Hub endpoint metadata did not identify a supported region for this account scope.")
        payload = collection.finish(
            account_id=context.security.account_id,
            regions=regions,
            metadata={
                "endpoint_strategy": self._endpoint_strategy(context),
                "explicit_region_scope": context.options.has_explicit_region_scope(),
                "selected_regions": tuple(regions),
                "unsupported_regions": tuple(self._unsupported_regions_for_selection(context, regions)),
            },
        )
        context.data.set("cost_optimization_hub_recommendations", payload)
        return payload

    def collect_operation(
        self,
        client: Any,  # noqa: ANN401
        *,
        operation_name: str,
        result_keys: tuple[str, ...],
        request_parameters: dict[str, Any] | None = None,
        source: str,
        region: str,
        warnings: list[str],
        statuses: list[str],
        status_details: list[dict[str, str]],
    ) -> list[dict[str, Any]]:
        """Retain the public helper with bounded, fail-closed operation reads."""
        result = AwsNativeOperationReader().read(client, operation_name=operation_name, result_keys=result_keys, request_parameters=request_parameters)
        if result.status != "complete":
            statuses.append(result.status)
            status_details.append({"region": region, "operation": operation_name, "status": result.status, "code": result.code})
            warnings.append(f"{source} unavailable in {region} ({result.code}).")
        return list(result.items)

    def normalize_hub_record(  # noqa: D102
        self,
        item: dict[str, Any],
        *,
        region: str,
    ) -> AwsNativeRecommendationRecord:
        recommendation_id = (
            first_text(
                item,
                "recommendationId",
                "recommendationIdentifier",
                "resourceId",
                "resourceArn",
            )
            or ""
        )
        resource_arn = first_text(item, "resourceArn", "accountResourceArn")
        resource_id = first_text(item, "resourceId", "resourceArn") or recommendation_id
        estimated = extract_estimated_savings(item)
        service = first_text(item, "service", "serviceName") or "AWS"
        return AwsNativeRecommendationRecord(
            source="cost_optimization_hub",
            recommendation_id=str(recommendation_id),
            recommendation_type=str(
                first_text(item, "actionType", "recommendationType", "type") or "recommendation",
            ),
            service=service,
            resource_type=str(
                first_text(
                    item,
                    "resourceType",
                    "currentResourceType",
                    "recommendedResourceType",
                )
                or "AWS resource",
            ),
            resource_id=str(resource_id),
            resource_arn=str(resource_arn) if resource_arn else None,
            region=str(first_text(item, "region") or region),
            finding=str(
                first_text(item, "summary", "description", "finding") or "",
            ),
            confidence=str(
                first_text(item, "confidence") or "",
            ),
            estimated_monthly_savings=estimated.get("amount"),
            currency=estimated.get("currency"),
            current_configuration=get_dict(item.get("currentResourceSummary")),
            recommended_configuration=get_dict(item.get("recommendedResourceSummary")),
            raw_summary=compact_dict(item),
        )

    def get_regions(self, context: ScannerContext) -> list[str]:  # noqa: D102
        if context.options.has_explicit_region_scope():
            return sorted(context.options.get_selected_regions())
        try:
            return sorted(context.security.session.get_available_regions("cost-optimization-hub"))
        except Exception:  # noqa: BLE001
            return []

    def create_client(self, context: ScannerContext, region: str) -> Any:  # noqa: ANN401, D102
        return context.security.create_client(
            "cost-optimization-hub",
            region_name=region,
            collector_name="CostOptimizationHubRecommendationCollector",
        )

    def _endpoint_strategy(self, context: ScannerContext) -> str:
        if context.options.has_explicit_region_scope():
            return "explicit_region_override"
        return "sdk_service_regions_intersected_with_account_enabled_regions"

    def _unsupported_regions_for_selection(
        self,
        context: ScannerContext,
        regions: list[str],
    ) -> list[str]:
        if not context.options.has_explicit_region_scope():
            return []
        get_sdk_regions = getattr(
            context.security.session,
            "get_sdk_available_regions",
            None,
        )
        if get_sdk_regions is None:
            return []
        try:
            supported = {str(region) for region in get_sdk_regions("cost-optimization-hub")}
        except Exception:  # noqa: BLE001
            return []
        if not supported:
            return []
        return sorted(region for region in regions if region not in supported)

    def _classify_operation_status(self, exc: Exception) -> str:
        code = AwsNativeOperationReader.error_code(exc)
        status = AwsNativeOperationReader.classify_error_code(code)
        if status == "permission_limited":
            return "permission_denied"
        if status == "not_enabled":
            return "service_not_enabled"
        if code in {"ConnectTimeoutError", "ReadTimeoutError", "TimeoutError"}:
            return "timeout"
        return "endpoint_unavailable"

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="CostOptimizationHubRecommendationReviewScanner",
            implementation_module="unio_collector.scanners.aws_native.cost_hub_scanner",
        )
