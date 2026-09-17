from __future__ import annotations  # noqa: D100

from datetime import UTC, datetime
from typing import Any

from unio_collector.aws.backup.rule import BackupRuleRecord


def get_calculated_delete_at(point: dict[str, Any]) -> datetime | None:  # noqa: D103
    lifecycle = point.get("CalculatedLifecycle")
    if not isinstance(lifecycle, dict):
        lifecycle = point.get("Lifecycle")
    if not isinstance(lifecycle, dict):
        return None
    value = lifecycle.get("DeleteAt")
    return value if isinstance(value, datetime) else None


def get_calculated_retention_days(  # noqa: D103
    point: dict[str, Any],
    created: object,
) -> int | None:
    lifecycle = point.get("Lifecycle")
    if isinstance(lifecycle, dict):
        delete_after_days = lifecycle.get("DeleteAfterDays")
        if isinstance(delete_after_days, int):
            return delete_after_days
    delete_at = get_calculated_delete_at(point)
    if not isinstance(created, datetime) or delete_at is None:
        return None
    created_at = created
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    if delete_at.tzinfo is None:
        delete_at = delete_at.replace(tzinfo=UTC)
    return max((delete_at - created_at).days, 0)


def get_backup_plan_arn(  # noqa: D103
    plan_summary: dict[str, Any],
    plan_detail: dict[str, Any],
) -> str | None:
    for source in (plan_detail, plan_summary):
        value = source.get("BackupPlanArn")
        if value is not None:
            return str(value)
    return None


def build_backup_rule_records(  # noqa: D103
    plan: dict[str, Any],
    vault_names: set[str],
) -> list[BackupRuleRecord]:
    rules: list[BackupRuleRecord] = []
    for rule in plan.get("Rules", []):
        if not isinstance(rule, dict):
            continue
        lifecycle = rule.get("Lifecycle")
        if not isinstance(lifecycle, dict):
            lifecycle = {}
        copy_actions = [copy_action for copy_action in rule.get("CopyActions", []) if isinstance(copy_action, dict)]
        target_vault_name = str(rule.get("TargetBackupVaultName")) if rule.get("TargetBackupVaultName") is not None else None
        target_vault_exists = target_vault_name in vault_names if target_vault_name is not None else None
        rules.append(
            BackupRuleRecord(
                rule_name=str(rule.get("RuleName") or "unnamed-rule"),
                target_backup_vault_name=target_vault_name,
                schedule_expression=(str(rule.get("ScheduleExpression")) if rule.get("ScheduleExpression") is not None else None),
                delete_after_days=get_int_value(lifecycle.get("DeleteAfterDays")),
                move_to_cold_storage_after_days=get_int_value(
                    lifecycle.get("MoveToColdStorageAfterDays"),
                ),
                copy_action_count=len(copy_actions),
                copy_destinations=get_copy_action_destinations(copy_actions),
                target_vault_exists=target_vault_exists,
            ),
        )
    return rules


def get_copy_action_destinations(copy_actions: list[dict[str, Any]]) -> list[str]:  # noqa: D103
    destinations: list[str] = []
    for copy_action in copy_actions:
        destination = copy_action.get("DestinationBackupVaultArn")
        if destination is not None:
            destinations.append(str(destination))
    return destinations


def get_string_list(value: object) -> list[str]:  # noqa: D103
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None]


def get_int_value(value: object) -> int | None:  # noqa: D103
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def get_datetime_value(value: object) -> datetime | None:  # noqa: D103
    return value if isinstance(value, datetime) else None


def normalize_backup_selection_detail_mode(value: object) -> str:  # noqa: D103
    mode = str(value or "full").strip().lower().replace("_", "-")
    if mode in {"full", "summary"}:
        return mode
    msg = "Backup selection_detail_mode must be one of 'full' or 'summary'."
    raise ValueError(msg)
