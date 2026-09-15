from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws.response_admission import ProviderResponseError, require_response_bool, require_response_mapping, require_response_string

if TYPE_CHECKING:
    from unio_collector.aws.dynamodb.table import DynamoDbTableDetail


class DynamoDbTableClassifier:
    """Interpret DynamoDB table metadata without owning AWS collection."""

    def is_active_table(self, table: dict[str, Any]) -> bool:  # noqa: D102
        return str(table.get("TableStatus") or "").upper() == "ACTIVE"

    def is_pay_per_request_table(self, table: dict[str, Any]) -> bool:  # noqa: D102
        return self.get_billing_mode(table) == "PAY_PER_REQUEST"

    def is_provisioned_table(self, table: dict[str, Any]) -> bool:  # noqa: D102
        return self.get_billing_mode(table) == "PROVISIONED"

    def get_billing_mode(self, table: dict[str, Any]) -> str:  # noqa: D102
        summary = table.get("BillingModeSummary")
        if "BillingModeSummary" in table:
            mode = require_response_string(require_response_mapping(summary).get("BillingMode"))
            if mode not in {"PROVISIONED", "PAY_PER_REQUEST"}:
                raise ProviderResponseError
            return mode
        return "PROVISIONED"

    def is_standard_ia_table(self, table: dict[str, Any]) -> bool:  # noqa: D102
        summary = table.get("TableClassSummary")
        if not isinstance(summary, dict):
            return False
        return str(summary.get("TableClass") or "").upper() in {
            "STANDARD_INFREQUENT_ACCESS",
            "STANDARD_IA",
        }

    def has_stream_enabled(self, table: dict[str, Any]) -> bool:  # noqa: D102
        stream = table.get("StreamSpecification")
        if stream is None:
            return False
        return require_response_bool(require_response_mapping(stream).get("StreamEnabled"))

    def is_pitr_enabled(self, response: dict[str, Any]) -> bool:  # noqa: D102
        backups = require_response_mapping(require_response_mapping(response).get("ContinuousBackupsDescription"))
        recovery = require_response_mapping(backups.get("PointInTimeRecoveryDescription"))
        status = require_response_string(recovery.get("PointInTimeRecoveryStatus")).upper()
        if status not in {"ENABLED", "DISABLED"}:
            raise ProviderResponseError
        return status == "ENABLED"

    def is_ttl_enabled(self, response: dict[str, Any]) -> bool:  # noqa: D102
        description = require_response_mapping(require_response_mapping(response).get("TimeToLiveDescription"))
        status = require_response_string(description.get("TimeToLiveStatus")).upper()
        if status not in {"ENABLED", "DISABLED", "ENABLING", "DISABLING"}:
            raise ProviderResponseError
        return status == "ENABLED"

    def has_provisioned_capacity(self, tables: list[dict[str, Any]]) -> bool:  # noqa: D102
        return any(self.is_provisioned_table(table) or self.count_provisioned_global_secondary_indexes(table) > 0 for table in tables)

    def count_provisioned_global_secondary_indexes(  # noqa: D102
        self,
        table: dict[str, Any],
    ) -> int:
        return sum(1 for index in self.get_global_secondary_indexes(table) if isinstance(index.get("ProvisionedThroughput"), dict))

    def get_global_secondary_indexes(  # noqa: D102
        self,
        table: dict[str, Any],
    ) -> list[dict[str, Any]]:
        indexes = table.get("GlobalSecondaryIndexes")
        if not isinstance(indexes, list):
            return []
        return [index for index in indexes if isinstance(index, dict)]

    def collect_tables_without_feature_status(  # noqa: D102
        self,
        table_details: list[DynamoDbTableDetail],
        *,
        enabled_table_names: set[str],
        error_method_name: str,
    ) -> list[str]:
        names: list[str] = []
        for detail in table_details:
            if not detail.table_name or detail.table_name in enabled_table_names:
                continue
            if self.detail_has_collection_error(detail, error_method_name):
                continue
            names.append(detail.table_name)
        return sorted(names)

    def detail_has_collection_error(  # noqa: D102
        self,
        detail: DynamoDbTableDetail,
        method_name: str,
    ) -> bool:
        prefix = f"{method_name}:"
        return any(error.startswith((prefix, "table_detail:")) for error in detail.permission_errors)

    def collect_provisioned_tables_without_autoscaling(  # noqa: D102
        self,
        tables: list[dict[str, Any]],
        scalable_targets: list[dict[str, Any]],
    ) -> list[str]:
        target_resource_ids = self.collect_scalable_target_resource_ids(
            scalable_targets,
        )
        names = [
            table_name
            for table in tables
            if self.is_provisioned_table(table)
            if (table_name := self.get_table_name(table))
            if f"table/{table_name}" not in target_resource_ids
        ]
        return sorted(names)

    def collect_provisioned_gsis_without_autoscaling(  # noqa: D102
        self,
        tables: list[dict[str, Any]],
        scalable_targets: list[dict[str, Any]],
    ) -> list[str]:
        target_resource_ids = self.collect_scalable_target_resource_ids(
            scalable_targets,
        )
        names: list[str] = []
        for table in tables:
            table_name = self.get_table_name(table)
            if not table_name:
                continue
            for index in self.get_global_secondary_indexes(table):
                index_name = str(index.get("IndexName") or "").strip()
                if not index_name or not isinstance(
                    index.get("ProvisionedThroughput"),
                    dict,
                ):
                    continue
                resource_id = f"table/{table_name}/index/{index_name}"
                if resource_id not in target_resource_ids:
                    names.append(f"{table_name}/{index_name}")
        return sorted(names)

    def collect_scalable_target_resource_ids(  # noqa: D102
        self,
        scalable_targets: list[dict[str, Any]],
    ) -> set[str]:
        return {resource_id for target in scalable_targets if (resource_id := str(target.get("ResourceId") or "").strip())}

    def get_provisioned_read_capacity(self, table: dict[str, Any]) -> int:  # noqa: D102
        throughput = table.get("ProvisionedThroughput")
        if "ProvisionedThroughput" not in table and self.is_pay_per_request_table(table):
            return 0
        return self.get_int(require_response_mapping(throughput).get("ReadCapacityUnits"))

    def get_provisioned_write_capacity(self, table: dict[str, Any]) -> int:  # noqa: D102
        throughput = table.get("ProvisionedThroughput")
        if "ProvisionedThroughput" not in table and self.is_pay_per_request_table(table):
            return 0
        return self.get_int(require_response_mapping(throughput).get("WriteCapacityUnits"))

    def get_table_name(self, table: dict[str, Any]) -> str:  # noqa: D102
        return str(table.get("TableName") or "").strip()

    def get_int(self, value: Any) -> int:  # noqa: ANN401, D102
        if type(value) is int and value >= 0:
            return value
        raise ProviderResponseError
