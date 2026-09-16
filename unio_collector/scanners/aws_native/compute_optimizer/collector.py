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
    first_dict,
    first_text,
    get_dict,
)
from unio_collector.scanners.aws_native.collection.reader import AwsNativeOperationReader
from unio_collector.scanners.aws_native.status_policy import (
    AwsNativeRecommendationStatusPolicy,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class ComputeOptimizerRecommendationReviewCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    operations = (
        (
            "get_ec2_instance_recommendations",
            "instanceRecommendations",
            "EC2 instance",
            "Amazon EC2",
        ),
        (
            "get_ebs_volume_recommendations",
            "volumeRecommendations",
            "EBS volume",
            "Amazon EBS",
        ),
        (
            "get_lambda_function_recommendations",
            "lambdaFunctionRecommendations",
            "Lambda function",
            "AWS Lambda",
        ),
        (
            "get_rds_database_recommendations",
            "rdsDBRecommendations",
            "RDS database",
            "Amazon RDS",
        ),
        (
            "get_ecs_service_recommendations",
            "ecsServiceRecommendations",
            "ECS service",
            "Amazon ECS",
        ),
        (
            "get_idle_recommendations",
            "idleRecommendations",
            "Idle resource",
            "AWS",
        ),
    )

    def collect(self, context: ScannerContext) -> dict[str, Any]:
        """Collect bounded provider facts before private recommendation analysis."""
        regions = self.get_regions(context)
        collection = AwsNativeCollectionCoordinator("compute_optimizer")
        for region in regions:
            client = self.create_client(context, region)
            collection.operation(
                client,
                operation="get_recommendation_summaries",
                result_keys=("recommendationSummaries", "RecommendationSummaries"),
                region=region,
                label="Compute Optimizer summary",
            )
            for operation, result_key, resource_type, service in self.operations:
                collection.operation(
                    client,
                    operation=operation,
                    result_keys=(result_key,),
                    region=region,
                    label=f"Compute Optimizer {operation}",
                    normalize=partial(
                        self.normalize_compute_optimizer_record, operation_name=operation, resource_type=resource_type, service=service, region=region
                    ),
                )
                if collection.stop_recommendations:
                    break
            if collection.stop_recommendations:
                if collection.record_limit_reached:
                    collection.warnings.append(
                        f"Compute Optimizer recommendation ingestion was capped at {MAX_NATIVE_RECOMMENDATION_RECORDS} records for this scan."
                    )
                break
        if not regions:
            collection.unavailable(region="none", operation="region_resolution", code="MissingRegionScope")
            collection.warnings.append("Compute Optimizer region scope was unavailable (MissingRegionScope).")
        payload = collection.finish(account_id=context.security.account_id, regions=regions)
        context.data.set("compute_optimizer_recommendations", payload)
        return payload

    def collect_summaries(  # noqa: D102
        self,
        client: Any,  # noqa: ANN401
        *,
        region: str,
        warnings: list[str],
        statuses: list[str],
    ) -> list[dict[str, Any]]:
        try:
            return self.collect_paginated_items(
                client,
                operation_name="get_recommendation_summaries",
                result_keys=("recommendationSummaries", "RecommendationSummaries"),
            )
        except Exception as exc:  # noqa: BLE001
            self.record_exception(
                warnings,
                statuses,
                source="Compute Optimizer summary",
                region=region,
                exc=exc,
            )
            return []

    def collect_operation_records(
        self,
        client: Any,  # noqa: ANN401
        *,
        operation_name: str,
        result_key: str,
        resource_type: str,
        service: str,
        region: str,
        warnings: list[str],
        statuses: list[str],
    ) -> list[AwsNativeRecommendationRecord]:
        """Preserve the public helper with validated, bounded provider records."""
        collection = AwsNativeCollectionCoordinator("compute_optimizer")
        collection.operation(
            client,
            operation=operation_name,
            result_keys=(result_key,),
            region=region,
            label=f"Compute Optimizer {operation_name}",
            normalize=partial(
                self.normalize_compute_optimizer_record, operation_name=operation_name, resource_type=resource_type, service=service, region=region
            ),
        )
        warnings.extend(collection.warnings)
        statuses.extend(status for status in collection.statuses if status != "complete")
        return collection.records

    def normalize_compute_optimizer_record(  # noqa: D102
        self,
        item: dict[str, Any],
        *,
        operation_name: str,
        resource_type: str,
        service: str,
        region: str,
    ) -> AwsNativeRecommendationRecord:
        resource_arn = first_text(
            item,
            "instanceArn",
            "volumeArn",
            "functionArn",
            "dbInstanceArn",
            "serviceArn",
            "resourceArn",
        )
        resource_id = (
            first_text(
                item,
                "instanceName",
                "volumeArn",
                "functionArn",
                "dbInstanceIdentifier",
                "serviceName",
                "resourceId",
                "resourceArn",
            )
            or resource_arn
            or ""
        )
        option = first_dict(
            item,
            "recommendationOptions",
            "volumeRecommendationOptions",
            "lambdaFunctionRecommendationOptions",
            "rdsDBRecommendationOptions",
            "serviceRecommendationOptions",
        )
        estimated = extract_estimated_savings(option or item)
        recommendation_type = operation_name.removeprefix("get_").removesuffix(
            "_recommendations",
        )
        return AwsNativeRecommendationRecord(
            source="compute_optimizer",
            recommendation_id=(f"compute-optimizer:{region}:{recommendation_type}:{resource_id}"),
            recommendation_type=recommendation_type,
            service=service,
            resource_type=resource_type,
            resource_id=str(resource_id),
            resource_arn=str(resource_arn) if resource_arn else None,
            region=region,
            finding=str(
                item.get("finding") or item.get("findingReasonCode") or "",
            ),
            confidence=str(
                item.get("confidence") or "",
            ),
            estimated_monthly_savings=estimated.get("amount"),
            currency=estimated.get("currency"),
            current_configuration=get_dict(item.get("currentConfiguration")),
            recommended_configuration=get_dict(option),
            raw_summary=compact_dict(item),
        )

    def get_regions(self, context: ScannerContext) -> list[str]:  # noqa: D102
        selected = context.options.get_selected_regions()
        if selected:
            return sorted(selected)
        try:
            return context.ec2.get_regions()
        except Exception:  # noqa: BLE001
            return []

    def create_client(self, context: ScannerContext, region: str) -> Any:  # noqa: ANN401, D102
        return context.security.create_client(
            "compute-optimizer",
            region_name=region,
            collector_name="ComputeOptimizerRecommendationCollector",
        )

    def collect_paginated_items(self, client: Any, *, operation_name: str, result_keys: tuple[str, ...]) -> list[dict[str, Any]]:  # noqa: ANN401
        """Preserve the list helper only for explicitly complete bounded reads."""
        result = AwsNativeOperationReader().read(client, operation_name=operation_name, result_keys=result_keys)
        if result.status != "complete":
            message = "AWS-native operation did not return complete bounded evidence."
            raise ValueError(message)
        return list(result.items)

    def record_exception(  # noqa: D102
        self,
        warnings: list[str],
        statuses: list[str],
        *,
        source: str,
        region: str,
        exc: Exception,
    ) -> None:
        status = AwsNativeRecommendationStatusPolicy().classify_exception(exc)
        code = AwsNativeOperationReader.error_code(exc)
        statuses.append(status)
        warnings.append(f"{source} unavailable in {region} ({code}).")

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="ComputeOptimizerRecommendationReviewScanner",
            implementation_module="unio_collector.scanners.aws_native.compute_optimizer_scanner",
        )
