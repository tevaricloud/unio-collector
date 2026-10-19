"""Complete synthetic Backup SDK response branches for the actual inventory producer."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from tools.collector_serverless.base import synthetic_arn

if TYPE_CHECKING:
    from tools.collector_backup.session import SyntheticBackupSession


class SyntheticBackupClient:
    """Retain requests and reject only explicit synthetic provider operations."""

    def __init__(self, session: SyntheticBackupSession, region: str) -> None:
        """Bind one isolated provider or exact Backup note parent."""
        self.session, self.region = session, region

    def can_paginate(self, _operation: str) -> bool:
        """Use the producer's actual explicit token-page path."""
        return False

    def _arn(self, service: str, resource: str) -> str:
        """Handle the declared synthetic  arn operation locally."""
        value = synthetic_arn(service, resource)
        return value.replace(":eu-west-2:", "::" if service == "iam" else ":" + self.region + ":")

    def _call(self, operation: str) -> None:
        """Handle the declared synthetic  call operation locally."""
        self.session.calls.append(operation + ":" + self.region)
        variant = self.session.variant
        root = operation == "list_backup_vaults"
        if (
            (root and variant in {"denied", "unsupported", "failure"})
            or (variant == "partial" and operation == "get_backup_plan")
            or (variant == "selection_denied" and operation == "get_backup_selection")
            or (variant == "tag_denied" and operation == "list_tags")
        ):
            code = {"denied": "AccessDeniedException", "unsupported": "UnknownOperationException", "failure": "InternalFailure"}.get(
                variant, "AccessDeniedException"
            )
            raise ClientError({"Error": {"Code": code, "Message": "synthetic-customer-provider diagnostic"}}, operation)

    def list_backup_vaults(self, **_kwargs: object) -> dict[str, Any]:
        """Handle the declared synthetic list backup vaults operation locally."""
        self._call("list_backup_vaults")
        return {
            "BackupVaultList": []
            if self.session.variant == "empty"
            else [
                {
                    "BackupVaultName": "synthetic-customer-vault",
                    "BackupVaultArn": None if self.session.variant == "nullable" else self._arn("backup", "backup-vault:synthetic-customer-vault"),
                    "NumberOfRecoveryPoints": None if self.session.variant == "nullable" else 2,
                    "EncryptionKeyArn": None if self.session.variant == "nullable" else self._arn("kms", "key/synthetic-customer-key"),
                }
            ]
        }

    def list_tags(self, **_kwargs: object) -> dict[str, Any]:
        """Handle the declared synthetic list tags operation locally."""
        self._call("list_tags")
        return {"Tags": {"Owner": "synthetic-customer-owner", "synthetic-customer-tag": "synthetic-customer-value", "Environment": "production"}}

    def list_backup_plans(self, **_kwargs: object) -> dict[str, Any]:
        """Handle the declared synthetic list backup plans operation locally."""
        self._call("list_backup_plans")
        return {
            "BackupPlansList": []
            if self.session.variant == "empty"
            else [
                {
                    "BackupPlanId": "synthetic-customer-plan",
                    "BackupPlanArn": None if self.session.variant == "nullable" else self._arn("backup", "backup-plan:synthetic-customer-plan"),
                    "BackupPlanName": "synthetic-customer-plan-name",
                    "CreationDate": None if self.session.variant == "nullable" else datetime(2025, 1, 1, tzinfo=UTC),
                    "LastExecutionDate": None if self.session.variant == "nullable" else datetime(2026, 9, 1, tzinfo=UTC),
                }
            ]
        }

    def get_backup_plan(self, **_kwargs: object) -> dict[str, Any]:
        """Handle the declared synthetic get backup plan operation locally."""
        self._call("get_backup_plan")
        return {
            "BackupPlanArn": None if self.session.variant == "nullable" else self._arn("backup", "backup-plan:synthetic-customer-plan"),
            "BackupPlan": {
                "BackupPlanName": "synthetic-customer-plan-name",
                "Rules": [
                    {
                        "RuleName": "synthetic-customer-rule",
                        "TargetBackupVaultName": None if self.session.variant == "nullable" else "synthetic-customer-vault",
                        "ScheduleExpression": None if self.session.variant == "nullable" else "cron(0 5 ? * * *)",
                        "Lifecycle": {} if self.session.variant == "nullable" else {"DeleteAfterDays": 730, "MoveToColdStorageAfterDays": 30},
                        "CopyActions": [{"DestinationBackupVaultArn": self._arn("backup", "backup-vault:synthetic-customer-copy")}],
                    },
                    {"RuleName": "synthetic-customer-no-lifecycle", "TargetBackupVaultName": None, "ScheduleExpression": None},
                ],
            },
        }

    def list_backup_selections(self, **_kwargs: object) -> dict[str, Any]:
        """Handle the declared synthetic list backup selections operation locally."""
        self._call("list_backup_selections")
        return {
            "BackupSelectionsList": [
                {
                    "SelectionId": "synthetic-customer-selection-" + str(index),
                    "SelectionName": "synthetic-customer-selection-name",
                    "CreationDate": None if self.session.variant == "nullable" else datetime(2025, 1, 1, tzinfo=UTC),
                }
                for index in (1, 2)
            ]
        }

    def get_backup_selection(self, **kwargs: object) -> dict[str, Any]:
        """Handle the declared synthetic get backup selection operation locally."""
        self._call("get_backup_selection")
        broad = str(kwargs["SelectionId"]).endswith("1")
        return {
            "BackupSelection": {
                "SelectionName": "synthetic-customer-selection-name",
                "IamRoleArn": None if self.session.variant == "nullable" else self._arn("iam", "role/synthetic-customer-backup-role"),
                "Resources": None
                if self.session.variant == "nullable"
                else [self._arn("ec2", "volume/synthetic-customer-*") if broad else self._arn("rds", "db:synthetic-customer-database")],
                "NotResources": None if self.session.variant == "nullable" else [self._arn("ec2", "volume/synthetic-customer-excluded")],
                "Conditions": {}
                if broad or self.session.variant == "nullable"
                else {
                    kind: [{"ConditionKey": "aws:ResourceTag/synthetic-customer-key", "ConditionValue": "synthetic-customer-condition"}]
                    for kind in ("StringEquals", "StringNotEquals", "StringLike", "StringNotLike")
                },
                "ListOfTags": []
                if broad or self.session.variant == "nullable"
                else [{"ConditionType": "STRINGEQUALS", "ConditionKey": "synthetic-customer-key", "ConditionValue": "synthetic-customer-tag-condition"}],
            }
        }

    def list_recovery_points_by_backup_vault(self, **_kwargs: object) -> dict[str, Any]:
        """Populate old expired and young completed records without collector-side age filtering."""
        self._call("list_recovery_points_by_backup_vault")
        points = []
        for index, status in enumerate(("EXPIRED", "COMPLETED")):
            created = datetime(2024, 1, 1, tzinfo=UTC) if index == 0 else datetime(2026, 9, 20, tzinfo=UTC)
            retention = 365 if index == 0 else 730
            name = "COMPLETED" if self.session.variant == "literal_collision" else "synthetic-customer-database"
            nullable = self.session.variant == "nullable"
            points.append(
                {
                    "RecoveryPointArn": self._arn("backup", "recovery-point:synthetic-customer-point-" + str(index)),
                    "ResourceArn": None if nullable else self._arn("rds", "db:" + name),
                    "ResourceType": None if nullable else "RDS",
                    "ResourceName": None if nullable else name,
                    "Status": None if nullable else status,
                    "BackupSizeInBytes": None if nullable else 123456,
                    "CreationDate": None if nullable else created,
                    "CompletionDate": None if nullable else created + timedelta(days=1),
                    "CalculatedLifecycle": {} if nullable else {"DeleteAt": created + timedelta(days=retention)},
                    "Lifecycle": {} if nullable else {"DeleteAfterDays": retention},
                }
            )
        return {"RecoveryPoints": points}
