"""Accumulate bounded provider recommendations and operation completeness."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any

from unio_collector.aws_native_recommendations.recommendation.source_payload import AwsNativeRecommendationSourcePayload
from unio_collector.scanners.aws_native.collection.actions import AWS_NATIVE_ACTIONS
from unio_collector.scanners.aws_native.collection.normalization import MAX_NATIVE_RECOMMENDATION_RECORDS, deduplicate_strings
from unio_collector.scanners.aws_native.collection.reader import AwsNativeOperationReader

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws_native_recommendations.recommendation.record import AwsNativeRecommendationRecord
    from unio_collector.scanners.aws_native.collection.result import AwsNativeOperationResult


class AwsNativeCollectionCoordinator:
    """Keep provider order, finite values and explicit limits across operations."""

    def __init__(self, source: str) -> None:
        """Start one source collection without creating an AWS client."""
        self.source = source
        self.records: list[AwsNativeRecommendationRecord] = []
        self.summaries: list[dict[str, Any]] = []
        self.details: list[dict[str, object]] = []
        self.warnings: list[str] = []
        self.statuses: list[str] = []
        self._record_budget_used = 0
        self._recommendation_capped = False
        self._recommendation_invalid = False

    @property
    def record_limit_reached(self) -> bool:
        """Return whether further recommendation operations must be skipped."""
        return self._record_budget_used >= MAX_NATIVE_RECOMMENDATION_RECORDS or self._recommendation_capped

    @property
    def stop_recommendations(self) -> bool:
        """Stop when the budget is reached or malformed pages obscure its use."""
        return self.record_limit_reached or self._recommendation_invalid

    def operation(
        self,
        client: Any,  # noqa: ANN401
        *,
        operation: str,
        result_keys: tuple[str, ...],
        region: str,
        label: str,
        normalize: Callable[[dict[str, Any]], AwsNativeRecommendationRecord] | None = None,
        parameters: dict[str, Any] | None = None,
    ) -> None:
        """Read one existing operation within the source-wide record budget."""
        remaining = MAX_NATIVE_RECOMMENDATION_RECORDS - (len(self.summaries) if normalize is None else self._record_budget_used)
        result = AwsNativeOperationReader().read(
            client,
            operation_name=operation,
            result_keys=result_keys,
            request_parameters=parameters,
            limit=remaining,
        )
        self.details.append(result.detail(region=region, api_action=AWS_NATIVE_ACTIONS[operation]))
        self.statuses.append(result.status)
        if result.status != "complete":
            self.warnings.append(f"{label} unavailable in {region} ({result.code}).")
        if normalize is None:
            self.summaries.extend(result.items)
        else:
            self._record_budget_used += min(remaining, result.observed_count)
            self._recommendation_capped = self._recommendation_capped or result.status == "capped"
            self._recommendation_invalid = self._recommendation_invalid or result.stop_collection
            self._normalize(result, normalize, region=region, operation=operation)

    def _normalize(
        self,
        result: AwsNativeOperationResult,
        normalize: Callable[[dict[str, Any]], AwsNativeRecommendationRecord],
        *,
        region: str,
        operation: str,
    ) -> None:
        invalid = 0
        for row in result.items:
            try:
                self._validate_input(row)
                record = normalize(row)
                self._validate_record(record)
            except (TypeError, ValueError, InvalidOperation):
                invalid += 1
            else:
                self.records.append(record)
        if invalid:
            self.statuses.append("partial")
            self.details.append(
                {"region": region, "api_action": AWS_NATIVE_ACTIONS[operation], "status": "partial", "error_code": "MalformedRecord", "omitted_count": invalid}
            )
            self.warnings.append(f"AWS-native recommendation records were incomplete in {region} (MalformedRecord).")

    @staticmethod
    def _validate_input(row: dict[str, Any]) -> None:
        text_fields = (
            "recommendationId",
            "recommendationIdentifier",
            "resourceId",
            "resourceArn",
            "accountResourceArn",
            "instanceArn",
            "volumeArn",
            "functionArn",
            "dbInstanceArn",
            "serviceArn",
            "instanceName",
            "dbInstanceIdentifier",
            "serviceName",
            "confidence",
            "finding",
            "findingReasonCode",
            "recommendationSourceType",
            "implementationEffort",
            "summary",
            "description",
            "actionType",
            "recommendationType",
            "type",
            "resourceType",
            "currentResourceType",
            "recommendedResourceType",
            "region",
            "service",
        )
        if any(row.get(key) is not None and not isinstance(row[key], str) for key in text_fields):
            message = "AWS-native recommendation text or identity is malformed."
            raise ValueError(message)

    @staticmethod
    def _validate_record(record: AwsNativeRecommendationRecord) -> None:
        identity = (record.recommendation_id, record.resource_id, record.region, record.service, record.resource_type, record.recommendation_type)
        if not all(isinstance(value, str) and value.strip() for value in identity):
            message = "AWS-native recommendation identity is missing."
            raise ValueError(message)
        if record.estimated_monthly_savings is not None and not Decimal(record.estimated_monthly_savings).is_finite():
            message = "AWS-native recommendation savings value is non-finite."
            raise ValueError(message)

    def unavailable(self, *, region: str, operation: str, code: str, status: str = "unavailable") -> None:
        """Record unavailable scope without inventing a fallback region."""
        self.statuses.append("unavailable")
        self.details.append({"region": region, "type": operation, "status": status, "error_code": code})

    def finish(self, *, account_id: str, regions: list[str], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        """Serialize neutral rows and completeness before private analysis."""
        collection_status = self._collection_status()
        status = collection_status
        if collection_status == "complete":
            status = "recorded" if self.records else "recorded_no_recommendations"
        details = dict(metadata or {})
        details.update(
            {
                "operation_statuses": self.details,
                "collection_status": collection_status,
                "record_limit": MAX_NATIVE_RECOMMENDATION_RECORDS,
                "record_budget_used": self._record_budget_used,
                "summary_limit": MAX_NATIVE_RECOMMENDATION_RECORDS,
            }
        )
        payload = AwsNativeRecommendationSourcePayload(
            source=self.source,
            status=status,
            account_id=account_id,
            regions=tuple(regions),
            recommendation_count=len(self.records),
            summary_count=len(self.summaries),
            records=tuple(self.records),
            summaries=tuple(self.summaries),
            warnings=tuple(deduplicate_strings(self.warnings)),
            metadata=details,
        ).to_dict()
        payload["evidence_version"] = 1
        return payload

    def _collection_status(self) -> str:
        incomplete = [status for status in self.statuses if status != "complete"]
        if incomplete and self.records and any(status != "capped" for status in incomplete):
            return "partial"
        if "capped" in incomplete or self.record_limit_reached:
            return "capped"
        if "partial" in incomplete:
            return "partial" if self.records else "unavailable"
        for status in ("permission_limited", "not_enabled", "unavailable"):
            if status in incomplete:
                return status
        return "complete" if self.statuses else "unavailable"
