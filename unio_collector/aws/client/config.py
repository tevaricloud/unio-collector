from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from botocore.config import Config

from unio_collector.aws.rate.limit_rule import RateLimitRule
from unio_collector.runtime_diagnostics import RuntimeDiagnosticsConfig


def build_default_rate_limits() -> dict[str, RateLimitRule]:  # noqa: D103
    return {
        "backup": RateLimitRule(4.0, 4),
        "apigateway": RateLimitRule(2.0, 2),
        "apigatewayv2": RateLimitRule(2.0, 2),
        "bedrock": RateLimitRule(1.0, 1),
        "bedrock-agent": RateLimitRule(1.0, 1),
        "budgets": RateLimitRule(2.0, 2),
        "ce": RateLimitRule(1.0, 1),
        "cloudtrail": RateLimitRule(1.0, 1),
        "cloudfront": RateLimitRule(1.0, 1),
        "cloudwatch": RateLimitRule(2.0, 2),
        "config": RateLimitRule(1.5, 2),
        "dynamodb": RateLimitRule(8.0, 8),
        "ec2": RateLimitRule(4.0, 4),
        "ecs": RateLimitRule(2.0, 2),
        "elasticache": RateLimitRule(2.0, 2),
        "elbv2": RateLimitRule(3.0, 3),
        "eks": RateLimitRule(2.0, 2),
        "freetier": RateLimitRule(1.0, 1),
        "guardduty": RateLimitRule(1.5, 2),
        "iam": RateLimitRule(1.0, 1),
        "inspector2": RateLimitRule(1.5, 2),
        "kms": RateLimitRule(1.0, 1),
        "lambda": RateLimitRule(3.0, 3),
        "logs": RateLimitRule(3.0, 3),
        "macie2": RateLimitRule(1.5, 2),
        "opensearch": RateLimitRule(2.0, 2),
        "organizations": RateLimitRule(1.0, 1),
        "pricing": RateLimitRule(1.0, 2, 2.0),
        "rds": RateLimitRule(2.0, 2),
        "redshift": RateLimitRule(2.0, 2),
        "redshift-serverless": RateLimitRule(2.0, 2),
        "resourcegroupstaggingapi": RateLimitRule(2.0, 2),
        "s3": RateLimitRule(3.0, 3),
        "sagemaker": RateLimitRule(2.0, 2),
        "secretsmanager": RateLimitRule(1.0, 1),
        "securityhub": RateLimitRule(1.5, 2),
        "sts": RateLimitRule(2.0, 2),
        "wafv2": RateLimitRule(1.5, 2),
    }


def build_default_operation_rate_limits() -> dict[str, RateLimitRule]:  # noqa: D103
    return {
        "backup:GetBackupPlan": RateLimitRule(4.0, 4, 1.0),
        "backup:ListBackupSelections": RateLimitRule(4.0, 4, 1.0),
        "backup:ListRecoveryPointsByBackupVault": RateLimitRule(4.0, 4, 1.0),
        "backup:ListTags": RateLimitRule(4.0, 4, 1.0),
        "budgets:DescribeBudgets": RateLimitRule(2.0, 2, 1.0),
        "budgets:DescribeNotificationsForBudget": RateLimitRule(2.0, 2, 1.0),
        "budgets:DescribeSubscribersForNotification": RateLimitRule(2.0, 2, 1.0),
        "pricing:GetProducts": RateLimitRule(1.0, 2, 2.0),
        "ce:GetCostAndUsage": RateLimitRule(1.0, 1, 1.5),
        "cloudwatch:GetMetricStatistics": RateLimitRule(2.0, 2, 1.5),
        "cloudwatch:GetMetricData": RateLimitRule(1.0, 1, 1.5),
        "cloudfront:ListDistributions": RateLimitRule(1.0, 1, 1.0),
        "cloudfront:ListTagsForResource": RateLimitRule(2.0, 2, 1.0),
        "dynamodb:DescribeContinuousBackups": RateLimitRule(10.0, 10, 1.0),
        "dynamodb:DescribeTable": RateLimitRule(10.0, 10, 1.0),
        "dynamodb:DescribeTimeToLive": RateLimitRule(10.0, 10, 1.0),
        "dynamodb:ListTagsOfResource": RateLimitRule(8.0, 8, 1.0),
        "ecs:DescribeTaskDefinition": RateLimitRule(4.0, 4, 1.0),
        "freetier:GetAccountPlanState": RateLimitRule(1.0, 1, 1.0),
        "freetier:GetFreeTierUsage": RateLimitRule(1.0, 1, 1.0),
        "lambda:GetPolicy": RateLimitRule(4.0, 4, 1.0),
        "lambda:ListTags": RateLimitRule(6.0, 6, 1.0),
        "iam:GetAccountPasswordPolicy": RateLimitRule(4.0, 4, 1.0),
        "iam:GetAccountSummary": RateLimitRule(4.0, 4, 1.0),
        "iam:GetAccessKeyLastUsed": RateLimitRule(8.0, 8, 1.0),
        "iam:GetGroupPolicy": RateLimitRule(4.0, 4, 1.0),
        "iam:GetLoginProfile": RateLimitRule(8.0, 8, 1.0),
        "iam:GetRolePolicy": RateLimitRule(4.0, 4, 1.0),
        "iam:GetUserPolicy": RateLimitRule(4.0, 4, 1.0),
        "iam:ListAccessKeys": RateLimitRule(8.0, 8, 1.0),
        "iam:ListEntitiesForPolicy": RateLimitRule(4.0, 4, 1.0),
        "iam:ListGroups": RateLimitRule(4.0, 4, 1.0),
        "iam:ListGroupPolicies": RateLimitRule(4.0, 4, 1.0),
        "iam:ListMFADevices": RateLimitRule(8.0, 8, 1.0),
        "iam:ListRoles": RateLimitRule(4.0, 4, 1.0),
        "iam:ListRolePolicies": RateLimitRule(4.0, 4, 1.0),
        "iam:ListUsers": RateLimitRule(4.0, 4, 1.0),
        "iam:ListUserPolicies": RateLimitRule(4.0, 4, 1.0),
        "kms:ListKeys": RateLimitRule(4.0, 4, 1.0),
        "kms:DescribeKey": RateLimitRule(8.0, 8, 1.0),
        "kms:GetKeyRotationStatus": RateLimitRule(8.0, 8, 1.0),
        "rds:ListTagsForResource": RateLimitRule(4.0, 4, 1.0),
        "s3:GetBucketLifecycleConfiguration": RateLimitRule(16.0, 16, 1.0),
        "s3:GetBucketLocation": RateLimitRule(12.0, 12, 1.0),
        "s3:GetBucketNotificationConfiguration": RateLimitRule(12.0, 12, 1.0),
        "s3:GetBucketAcl": RateLimitRule(12.0, 12, 1.0),
        "s3:GetBucketPolicyStatus": RateLimitRule(12.0, 12, 1.0),
        "s3:GetBucketReplication": RateLimitRule(8.0, 8, 1.0),
        "s3:GetBucketTagging": RateLimitRule(12.0, 12, 1.0),
        "s3:GetBucketVersioning": RateLimitRule(16.0, 16, 1.0),
        "s3:GetPublicAccessBlock": RateLimitRule(12.0, 12, 1.0),
        "s3:ListBuckets": RateLimitRule(4.0, 4, 1.0),
        "s3:ListMultipartUploads": RateLimitRule(12.0, 12, 1.0),
        "s3control:GetPublicAccessBlock": RateLimitRule(4.0, 4, 1.0),
    }


@dataclass(frozen=True)
class AwsRuntimeConfig:  # noqa: D101
    max_workers: int = 16
    scanner_concurrency_enabled: bool = True
    scanner_max_workers: int = 6
    scanner_timeout_seconds: int = 300
    max_pool_connections: int = 32
    retry_mode: str = "standard"
    total_max_attempts: int = 6
    connect_timeout_seconds: int = 3
    read_timeout_seconds: int = 30
    telemetry_enabled: bool = True
    record_aws_cassette: Path | None = None
    replay_aws_cassette: Path | None = None
    confirm_live_aws_recording: bool = False
    diagnostics: RuntimeDiagnosticsConfig = field(
        default_factory=RuntimeDiagnosticsConfig,
    )
    rate_limits: dict[str, RateLimitRule] = field(
        default_factory=build_default_rate_limits,
    )
    operation_rate_limits: dict[str, RateLimitRule] = field(
        default_factory=build_default_operation_rate_limits,
    )

    def validate(self) -> None:  # noqa: C901, D102
        if self.max_workers <= 0:
            msg = "Runtime max_workers must be a positive integer."
            raise ValueError(msg)
        if self.scanner_max_workers <= 0:
            msg = "Runtime scanner_max_workers must be a positive integer."
            raise ValueError(msg)
        if self.scanner_timeout_seconds <= 0:
            msg = "Runtime scanner_timeout_seconds must be a positive integer."
            raise ValueError(
                msg,
            )
        if self.max_pool_connections <= 0:
            msg = "Runtime max_pool_connections must be a positive integer."
            raise ValueError(msg)
        if self.total_max_attempts <= 0:
            msg = "Runtime total_max_attempts must be a positive integer."
            raise ValueError(msg)
        if self.connect_timeout_seconds <= 0:
            msg = "Runtime connect_timeout_seconds must be a positive integer."
            raise ValueError(
                msg,
            )
        if self.read_timeout_seconds <= 0:
            msg = "Runtime read_timeout_seconds must be a positive integer."
            raise ValueError(msg)
        if self.retry_mode not in {"standard", "legacy"}:
            msg = "Runtime retry_mode must be 'standard' or 'legacy'."
            raise ValueError(msg)
        if self.record_aws_cassette and self.replay_aws_cassette:
            msg = "Use either AWS cassette record mode or replay mode, not both."
            raise ValueError(
                msg,
            )
        if self.record_aws_cassette and not self.confirm_live_aws_recording:
            msg = "AWS cassette record mode calls live AWS APIs. Re-run with --confirm-live-aws-recording to confirm this development-only recording run."
            raise ValueError(
                msg,
            )
        self.diagnostics.validate()
        for service, rule in self.rate_limits.items():
            rule.validate(key=f"defaults.{service}")
        for operation, rule in self.operation_rate_limits.items():
            rule.validate(key=f"operations.{operation}")

    def build_botocore_config(  # noqa: D102
        self,
        *,
        user_agent_extra: str = "UnioCollectorScanner/0.1",
        read_timeout_seconds: int | None = None,
    ) -> Config:
        self.validate()
        return Config(
            retries={
                "mode": self.retry_mode,
                "total_max_attempts": self.total_max_attempts,
            },
            connect_timeout=self.connect_timeout_seconds,
            read_timeout=read_timeout_seconds or self.read_timeout_seconds,
            max_pool_connections=self.max_pool_connections,
            user_agent_extra=user_agent_extra,
            parameter_validation=True,
        )

    def with_overrides(  # noqa: D102
        self,
        *,
        max_workers: int | None = None,
        scanner_max_workers: int | None = None,
        scanner_timeout_seconds: int | None = None,
        max_pool_connections: int | None = None,
        total_max_attempts: int | None = None,
        connect_timeout_seconds: int | None = None,
        read_timeout_seconds: int | None = None,
        record_aws_cassette: str | Path | None = None,
        replay_aws_cassette: str | Path | None = None,
        confirm_live_aws_recording: bool | None = None,
    ) -> AwsRuntimeConfig:
        updated = replace(
            self,
            max_workers=max_workers or self.max_workers,
            scanner_max_workers=scanner_max_workers or self.scanner_max_workers,
            scanner_timeout_seconds=(scanner_timeout_seconds or self.scanner_timeout_seconds),
            max_pool_connections=max_pool_connections or self.max_pool_connections,
            total_max_attempts=total_max_attempts or self.total_max_attempts,
            connect_timeout_seconds=(connect_timeout_seconds or self.connect_timeout_seconds),
            read_timeout_seconds=read_timeout_seconds or self.read_timeout_seconds,
            record_aws_cassette=(Path(record_aws_cassette) if record_aws_cassette is not None else self.record_aws_cassette),
            replay_aws_cassette=(Path(replay_aws_cassette) if replay_aws_cassette is not None else self.replay_aws_cassette),
            confirm_live_aws_recording=(confirm_live_aws_recording if confirm_live_aws_recording is not None else self.confirm_live_aws_recording),
        )
        updated.validate()
        return updated

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        return {
            "max_workers": self.max_workers,
            "scanner_concurrency_enabled": self.scanner_concurrency_enabled,
            "scanner_max_workers": self.scanner_max_workers,
            "scanner_timeout_seconds": self.scanner_timeout_seconds,
            "max_pool_connections": self.max_pool_connections,
            "retry_mode": self.retry_mode,
            "total_max_attempts": self.total_max_attempts,
            "connect_timeout_seconds": self.connect_timeout_seconds,
            "read_timeout_seconds": self.read_timeout_seconds,
            "telemetry_enabled": self.telemetry_enabled,
            "record_aws_cassette": (str(self.record_aws_cassette) if self.record_aws_cassette else None),
            "replay_aws_cassette": (str(self.replay_aws_cassette) if self.replay_aws_cassette else None),
            "diagnostics": self.diagnostics.convert_to_dict(),
            "rate_limits": {
                "defaults": {service: rule.convert_to_dict() for service, rule in sorted(self.rate_limits.items())},
                "operations": {operation: rule.convert_to_dict() for operation, rule in sorted(self.operation_rate_limits.items())},
            },
        }
