from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.inventory_helpers import (
    AwsInventoryValueHelper,
    RegionalInventoryCollectionHelper,
)
from unio_collector.aws.pagination import AwsPaginationHelper
from unio_collector.aws.xray.region_record import XRayRegionRecord

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext


class XRayInventoryCollector:
    """Collect read-only X-Ray metadata without retrieving trace documents."""

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
        self._pagination = AwsPaginationHelper()
        self._values = AwsInventoryValueHelper()
        self._regional_collection = RegionalInventoryCollectionHelper(
            self.session,
            account_id=self.account_id,
            audit_context=self.audit_context,
            collector_id="XRayInventoryCollector",
        )
        self._available_regions_cache: list[str] | None = None

    def collect_records(self) -> list[XRayRegionRecord]:  # noqa: D102
        return self._regional_collection.collect_region_records(
            regions=self.get_available_regions(),
            service="xray",
            operation=("GetGroups+GetSamplingRules+GetSamplingStatisticSummaries+GetEncryptionConfig"),
            collect_region=self._collect_region_record,
        )

    def _collect_region_record(self, region: str) -> list[XRayRegionRecord]:
        permission_errors: list[str] = []
        client = self._safe_client("xray", region, permission_errors)
        if client is None:
            return [
                XRayRegionRecord(
                    account_id=self.account_id,
                    region=region,
                    permission_errors=permission_errors,
                ),
            ]

        groups = self._collect_groups(client, permission_errors)
        sampling_rules = self._collect_sampling_rules(client, permission_errors)
        statistics = self._collect_sampling_statistics(client, permission_errors)
        encryption_type = self._collect_encryption_type(client, permission_errors)
        return [
            XRayRegionRecord(
                account_id=self.account_id,
                region=region,
                group_count=len(groups),
                sampling_rule_count=len(sampling_rules),
                custom_sampling_rule_count=sum(1 for rule in sampling_rules if self._is_custom_sampling_rule(rule)),
                sampling_statistics_count=len(statistics),
                sampled_trace_count=sum(self._get_int(item.get("SampledCount")) for item in statistics),
                request_count=sum(self._get_int(item.get("RequestCount")) for item in statistics),
                borrow_count=sum(self._get_int(item.get("BorrowCount")) for item in statistics),
                encryption_type=encryption_type,
                sample_group_names=self._limit_samples(
                    [str(group.get("GroupName")) for group in groups if group.get("GroupName")],
                ),
                sample_sampling_rule_names=self._limit_samples(
                    [str(rule.get("RuleName")) for rule in sampling_rules if rule.get("RuleName")],
                ),
                permission_errors=permission_errors,
            ),
        ]

    def _collect_groups(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        return self._collect_items(
            client,
            "get_groups",
            "Groups",
            permission_errors,
        )

    def _collect_sampling_rules(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        records = self._collect_items(
            client,
            "get_sampling_rules",
            "SamplingRuleRecords",
            permission_errors,
        )
        rules: list[dict[str, Any]] = []
        for record in records:
            rule = record.get("SamplingRule")
            if isinstance(rule, dict):
                rules.append(rule)
        return rules

    def _collect_sampling_statistics(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        return self._collect_items(
            client,
            "get_sampling_statistic_summaries",
            "SamplingStatisticSummaries",
            permission_errors,
        )

    def _collect_items(
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
                request_cursor_key="NextToken",
                response_cursor_keys=("NextToken", "nextToken"),
            )
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name=method_name,
                exc=exc,
            )
            return []
        return self._values.collect_dict_items(result.pages, result_key)

    def _collect_encryption_type(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> str | None:
        try:
            response = client.get_encryption_config()
        except Exception as exc:  # noqa: BLE001
            self._record_collection_error(
                permission_errors,
                method_name="get_encryption_config",
                exc=exc,
            )
            return None
        config = response.get("EncryptionConfig") if isinstance(response, dict) else None
        if not isinstance(config, dict):
            return None
        value = config.get("Type")
        return str(value) if value else None

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
        if aws_errors.is_expected_absence_error(exc):
            return
        code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
        item = f"{method_name}:{code}"
        if item not in errors:
            errors.append(item)

    def _is_custom_sampling_rule(self, rule: dict[str, Any]) -> bool:
        name = str(rule.get("RuleName") or "")
        return bool(name and name != "Default")

    def _get_int(self, value: Any) -> int:  # noqa: ANN401
        return self._values.get_int(value)

    def _limit_samples(self, values: list[str]) -> list[str]:
        return self._values.limit_samples(values)

    def get_available_regions(self) -> list[str]:  # noqa: D102
        if self._available_regions_cache is not None:
            return self._available_regions_cache
        if self.selected_regions:
            self._available_regions_cache = sorted(self.selected_regions)
            return self._available_regions_cache
        regions = self.session.get_available_regions("xray")
        self._available_regions_cache = sorted(regions)
        return self._available_regions_cache
