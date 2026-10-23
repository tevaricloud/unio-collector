"""Independent explicit fields of the five Backup inventory DTOs and their nested records."""

from unio_collector.privacy.s3.fields import fields

SCANNER = "backup-retention-review"
VAULT = frozenset(
    [
        "backup_vault_name",
        "backup_vault_arn",
        "account_id",
        "region",
        "recovery_point_count",
        "encryption_key_arn",
        "tags",
        "collection_errors",
        "tags_collected",
    ]
)
PLAN = frozenset(
    [
        "backup_plan_id",
        "backup_plan_arn",
        "backup_plan_name",
        "account_id",
        "region",
        "rules",
        "selections",
        "tags",
        "creation_date",
        "last_execution_date",
        "collection_errors",
        "tags_collected",
    ]
)
POINT = frozenset(
    [
        "recovery_point_arn",
        "backup_vault_name",
        "backup_vault_arn",
        "account_id",
        "region",
        "resource_arn",
        "resource_type",
        "resource_name",
        "status",
        "backup_size_bytes",
        "creation_date",
        "completion_date",
        "calculated_delete_at",
        "calculated_retention_days",
        "age_days",
    ]
)
RULE = frozenset(
    [
        "rule_name",
        "target_backup_vault_name",
        "schedule_expression",
        "delete_after_days",
        "move_to_cold_storage_after_days",
        "copy_action_count",
        "copy_destinations",
        "target_vault_exists",
    ]
)
SELECTION = frozenset(["selection_id", "selection_name", "iam_role_arn", "resources", "not_resources", "conditions", "list_of_tags", "creation_date"])
RULE_PATH = "records[].rules[]"
SELECTION_PATH = "records[].selections[]"
CONDITIONS = frozenset({"StringEquals", "StringNotEquals", "StringLike", "StringNotLike"})
FIELDS = {
    "": ("object", "safe_metadata", False),
    **fields("records regions records[].rules records[].selections records[].collection_errors", "array"),
    **fields("records[] metadata", "object"),
    **fields("regions[] records[].region", "string", "region"),
    **fields("records[].account_id", "string", "aws_account_id"),
    **fields("records[].backup_plan_id", "string", "resource_id"),
    **fields("records[].backup_plan_name records[].backup_vault_name", "string", "resource_name"),
    **fields("records[].resource_name records[].resource_type records[].status", "string", "free_text", nullable=True),
    **fields("records[].backup_vault_arn records[].backup_plan_arn records[].encryption_key_arn records[].resource_arn", "string", "arn", nullable=True),
    **fields("records[].recovery_point_arn", "string", "arn"),
    **fields("records[].recovery_point_count records[].backup_size_bytes records[].age_days", "count", "summary_count", nullable=True),
    **fields("records[].calculated_retention_days", "integer", "summary_count", nullable=True),
    **fields(
        "records[].creation_date records[].completion_date records[].calculated_delete_at records[].last_execution_date",
        "timestamp",
        "timestamp",
        nullable=True,
    ),
    **fields("records[].tags", "string_map", "tag_value"),
    **fields("records[].tags_collected metadata.collect_tags", "boolean"),
    **fields("records[].collection_errors[]", "string", "free_text"),
    **fields("metadata.older_than_days metadata.long_retention_days", "integer", "summary_count"),
    **fields("metadata.max_detail_workers", "positive", "summary_count"),
    **fields("metadata.selection_detail_mode", "detail_mode"),
    **fields(RULE_PATH + " " + SELECTION_PATH, "object"),
    **fields(RULE_PATH + ".rule_name " + SELECTION_PATH + ".selection_name", "string", "resource_name"),
    **fields(RULE_PATH + ".target_backup_vault_name", "string", "resource_name", nullable=True),
    **fields(RULE_PATH + ".schedule_expression", "string", "free_text", nullable=True),
    **fields(RULE_PATH + ".delete_after_days " + RULE_PATH + ".move_to_cold_storage_after_days", "integer", "summary_count", nullable=True),
    **fields(RULE_PATH + ".copy_action_count", "count", "summary_count"),
    **fields(RULE_PATH + ".copy_destinations", "array"),
    **fields(RULE_PATH + ".copy_destinations[]", "string", "arn"),
    **fields(RULE_PATH + ".target_vault_exists", "boolean", nullable=True),
    **fields(SELECTION_PATH + ".selection_id", "string", "resource_id"),
    **fields(SELECTION_PATH + ".iam_role_arn", "string", "arn", nullable=True),
    **fields(SELECTION_PATH + ".resources " + SELECTION_PATH + ".not_resources " + SELECTION_PATH + ".list_of_tags", "array"),
    **fields(SELECTION_PATH + ".resources[] " + SELECTION_PATH + ".not_resources[]", "string", "arn_or_name"),
    **fields(SELECTION_PATH + ".creation_date", "timestamp", "timestamp", nullable=True),
    **fields(SELECTION_PATH + ".conditions " + SELECTION_PATH + ".list_of_tags[]", "object"),
    **fields(SELECTION_PATH + ".list_of_tags[].ConditionType", "condition_type"),
    **fields(SELECTION_PATH + ".list_of_tags[].ConditionKey", "string", "free_text"),
    **fields(SELECTION_PATH + ".list_of_tags[].ConditionValue", "string", "free_text"),
    **{SELECTION_PATH + ".conditions." + kind: ("array", "safe_metadata", False) for kind in CONDITIONS},
    **{SELECTION_PATH + ".conditions." + kind + "[]": ("object", "safe_metadata", False) for kind in CONDITIONS},
    **{
        SELECTION_PATH + ".conditions." + kind + "[]." + key: ("string", "free_text", False)
        for kind in CONDITIONS
        for key in ("ConditionKey", "ConditionValue")
    },
}
