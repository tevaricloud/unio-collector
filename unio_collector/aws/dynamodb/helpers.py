# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from typing import Any

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.response_admission import iter_response_rows, require_response_string

DYNAMODB_RETENTION_DETAIL_MODES = {"full", "summary"}
DYNAMODB_METRIC_DETAIL_MODES = {"full", "summary"}
DYNAMODB_AUTOSCALING_DETAIL_MODES = {"full", "summary"}
DYNAMODB_TABLE_DETAIL_REGIONAL_MODES = {"full", "billing-active"}
TABLE_DETAIL_SKIPPED_ERROR = "table_detail:skipped_by_regional_collection_mode"
RETENTION_DETAIL_SKIPPED_ERRORS = (
    "describe_continuous_backups:skipped_by_retention_detail_mode",
    "describe_time_to_live:skipped_by_retention_detail_mode",
)
METRIC_DETAIL_SKIPPED_ERROR = "cloudwatch_metrics:skipped_by_metric_detail_mode"
AUTOSCALING_DETAIL_SKIPPED_ERROR = "application_autoscaling:skipped_by_autoscaling_detail_mode"


class DynamoDbHelperMixin:  # noqa: D101
    def _collect_application_autoscaling_items(
        self,
        client: Any,  # noqa: ANN401
        method_name: str,
        result_key: str,
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._pagination.collect_token_pages(
                client,
                method_name,
                result_key=result_key,
                request_parameters={"ServiceNamespace": "dynamodb"},
                request_cursor_key="NextToken",
                response_cursor_keys=("NextToken", "nextToken"),
            )
            return [item for item in iter_response_rows(result.pages, result_key) if require_response_string(item.get("ResourceId")).startswith("table/")]
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name=method_name,
                exc=exc,
            )
            return []

    def _safe_client(
        self,
        service_name: str,
        region: str,
        permission_errors: list[str],
    ) -> Any | None:  # noqa: ANN401
        try:
            return self.session.create_client(
                service_name,
                region_name=region,
                audit_context=self.audit_context,
            )
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name=f"{service_name}:CreateClient",
                exc=exc,
            )
            return None

    def _record_collection_error(
        self,
        errors: list[str],
        *,
        method_name: str,
        exc: Exception,
    ) -> None:
        code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
        item = f"{method_name}:{code}"
        if item not in errors:
            errors.append(item)

    def _extend_unique(self, target: list[str], values: list[str]) -> None:
        for value in values:
            if value not in target:
                target.append(value)

    def _limit_samples(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        samples: list[str] = []
        for value in values:
            if not value or value in seen:
                continue
            seen.add(value)
            samples.append(value)
            if len(samples) >= 10:  # noqa: PLR2004
                break
        return samples

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

    def _get_max_workers(self) -> int:
        runtime_config = getattr(self.session, "runtime_config", None)
        configured = getattr(runtime_config, "max_workers", 4)
        if not isinstance(configured, int) or configured <= 0:
            return 4
        return min(16, configured)
